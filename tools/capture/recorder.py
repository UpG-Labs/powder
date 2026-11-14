"""Crash-tolerant writers for the recording formats consumed by Powder.

This module deliberately has no mitmproxy dependency.  A network adapter gives it
decoded HTTP bodies and plaintext Ubisoft Connect demux chunks; this module owns
only framing, correlation, persistence, and a conservative completeness report.

Recordings are private working data.  Response bodies may contain account IDs,
friends, tickets, or other personal data.  Request headers are never accepted by
this API and therefore cannot accidentally be persisted.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from powder.server.constants import APP_ID, SPACE_ID
from powder.server.gamedata.build import ACTIONS_PATH, CONNECT_ALLOW, GAME_ALLOW, GUID, OFFERS_PATH
from powder.server.hostnames import CONNECT_HOSTS, DEMUX_HOST, GAME_HOSTS
from powder.server.transport.demux import pb

MAX_DEMUX_MESSAGE = 16 << 20
EXPECTED_OFFERS = 2_000
CHECKPOINT_EVENTS = 100
INVENTORY_PATH = re.compile(rf"/v1/profiles/({GUID})/inventory$")
ACHIEVEMENT_ZIP = re.compile(r"/orbit/uplay_launcher_3_0/assets/[0-9a-f]+\.zip$")
SHARED_GAME_HOSTS = {"public-ubiservices.ubi.com", "msr-public-ubiservices.ubi.com",
                     "public-im-ubiservices.ubi.com", "public-ws-ubiservices.ubi.com"}
REQUIRED_GAME_ENDPOINTS = {
    "application_configuration": f"/v2/applications/{APP_ID}/configuration",
    "primary_store": f"/v1/spaces/{SPACE_ID}/configs/primarystore",
    "events": f"/v4/spaces/{SPACE_ID}/configs/events",
    "items": f"/v1/spaces/{SPACE_ID}/items/all",
    "legacy_challenges": "/v2/spaces/global/ubiconnect/challenges/api/legacy/empty",
}


def _matches(rules, method: str, path: str) -> bool:
    base = path.split("?", 1)[0]
    return any(wanted == method and re.fullmatch(pattern, base) for wanted, pattern in rules)


def classify_http(method: str, host: str, path: str, app_id: str = "") -> str:
    """Return ``game``, ``connect``, or ``both`` without retaining request headers."""
    method, host, app_id = method.upper(), host.lower().rstrip("."), app_id.strip().lower()
    if app_id:
        return "game" if app_id == APP_ID else "connect"
    base = path.split("?", 1)[0]
    game = (_matches(GAME_ALLOW, method, path)
            or method == "GET" and (OFFERS_PATH.fullmatch(base) or ACTIONS_PATH.fullmatch(base)))
    connect = _matches(CONNECT_ALLOW, method, path)
    if host in set(CONNECT_HOSTS) - {DEMUX_HOST, "channel-service.upc.ubi.com"}:
        connect = True
    if host in set(GAME_HOSTS) - SHARED_GAME_HOSTS:
        game = True
    if game and not connect:
        return "game"
    if connect and not game:
        return "connect"
    return "both"


def _private(path: Path) -> None:
    """Best-effort owner-only POSIX permissions (Windows ignores chmod ACL details)."""
    try:
        path.chmod(0o600 if path.is_file() else 0o700)
    except OSError:
        pass


def _load(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"refusing to overwrite unreadable recording file {path}: {exc}") from exc


def _stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _atomic_json(path: Path, value, *, pretty: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    text = json.dumps(value, indent=1 if pretty else None,
                      separators=None if pretty else (",", ":"), ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    _private(tmp)
    os.replace(tmp, path)
    _private(path)


def _json_bytes(raw: bytes):
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def _kind(message: bytes) -> int | None:
    """The request/reply kind in a nested or flat demux service message."""
    fields = pb.try_decode(message)
    if not fields:
        return None
    top = pb.first(fields, 1)
    body = pb.try_decode(top) if isinstance(top, bytes) else fields if isinstance(top, int) else None
    if not body:
        return None
    field = next((f for f in body if f[0] != 1), None)
    return field[0] if field else None


@dataclass
class _DemuxStream:
    client: bytearray = field(default_factory=bytearray)
    server: bytearray = field(default_factory=bytearray)
    opening: dict[int, str] = field(default_factory=dict)
    channels: dict[int, str] = field(default_factory=dict)


class RecordingStore:
    """Persist HTTP and demux recordings in the exact formats Powder consumes.

    ``record_http`` receives already content-decoded response bytes.  ``feed_demux``
    receives arbitrary plaintext TCP chunks after TLS has been removed.  Every
    state-changing event is fsync'd to an append-only journal before canonical JSON
    files are atomically replaced, so opening the same directory resumes safely.
    """

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        _private(self.root)
        self.game_http: list[dict] = _load(self.root / "fixtures.json", [])
        self.connect_http: list[dict] = _load(self.root / "connect-fixtures.json", [])
        self.inventory: list[dict] = _load(self.root / "inventory-updates.json", [])
        self.issues: list[dict] = _load(self.root / "capture-issues.json", [])
        self.rmc: dict = _load(self.root / "fixtures-rmc.json", {})
        self.demux: dict = _load(self.root / "demux.json", {})
        expected = (("fixtures.json", self.game_http, list),
                    ("connect-fixtures.json", self.connect_http, list),
                    ("inventory-updates.json", self.inventory, list),
                    ("capture-issues.json", self.issues, list),
                    ("fixtures-rmc.json", self.rmc, dict),
                    ("demux.json", self.demux, dict))
        for name, value, kind in expected:
            if not isinstance(value, kind):
                raise ValueError(f"refusing to overwrite {self.root / name}: expected {kind.__name__}")
        self.demux.setdefault("client_version", None)
        self.demux.setdefault("patch_info", None)
        self.demux.setdefault("services", {})
        if not isinstance(self.demux["services"], dict):
            raise ValueError(f"refusing to overwrite {self.root / 'demux.json'}: services must be an object")
        self._http_seen = {
            "game": {_stable(e) for e in self.game_http},
            "connect": {_stable(e) for e in self.connect_http},
        }
        self._inventory_seen = {_stable(e) for e in self.inventory}
        self._issue_seen = {_stable(e) for e in self.issues}
        self._service_seen: set[tuple[str, str, str]] = set()
        for service, kinds in self.demux["services"].items():
            if not isinstance(service, str) or not isinstance(kinds, dict):
                continue
            for kind, replies in kinds.items():
                if isinstance(replies, list):
                    self._service_seen.update((service, str(kind), reply)
                                              for reply in replies if isinstance(reply, str))
        self._streams: dict[str, _DemuxStream] = {}
        self.journal_path = self.root / "capture-journal.jsonl"
        self._replay_journal()
        self._journal = open(self.journal_path, "a", encoding="utf-8", newline="\n")
        _private(self.journal_path)
        self._dirty_events = 0
        self.flush()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _replay_journal(self) -> None:
        if not self.journal_path.exists():
            return
        try:
            raw = self.journal_path.read_text(encoding="utf-8")
        except OSError:
            return
        # A crash may leave only the final line truncated; all earlier lines remain useful.
        valid = []
        for line in raw.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            valid.append(_stable(event))
            self._apply(event)
        repaired = "".join(line + "\n" for line in valid)
        if repaired != raw:
            tmp = self.journal_path.with_name(self.journal_path.name + ".tmp")
            with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                f.write(repaired)
                f.flush()
                os.fsync(f.fileno())
            _private(tmp)
            os.replace(tmp, self.journal_path)
            _private(self.journal_path)

    def _event(self, kind: str, value) -> bool:
        event = {"kind": kind, "value": value}
        if not self._would_change(event):
            return False
        self._journal.write(_stable(event) + "\n")
        self._journal.flush()
        os.fsync(self._journal.fileno())
        self._apply(event)
        self._dirty_events += 1
        # The journal is the crash-recovery source of truth.  Rewriting two
        # potentially large fixture arrays for every response would stall the
        # intercepted game, so checkpoint them periodically and at close.
        if self._dirty_events >= CHECKPOINT_EVENTS:
            self.flush()
        return True

    def _would_change(self, event: dict) -> bool:
        kind, value = event.get("kind"), event.get("value")
        if kind in ("http_game", "http_connect") and isinstance(value, dict):
            target = kind.removeprefix("http_")
            return _stable(value) not in self._http_seen[target]
        if kind == "http" and isinstance(value, dict):       # v1 journal compatibility
            key = _stable(value)
            return any(key not in self._http_seen[target] for target in ("game", "connect"))
        if kind == "inventory" and isinstance(value, dict):
            return _stable(value) not in self._inventory_seen
        if kind == "issue" and isinstance(value, dict):
            return _stable(value) not in self._issue_seen
        if kind == "demux_client_version" and isinstance(value, int):
            return self.demux.get("client_version") != value
        if kind == "demux_patch_info" and isinstance(value, str):
            return self.demux.get("patch_info") != value
        if kind == "demux_service" and isinstance(value, dict):
            key = (value.get("service"), str(value.get("service_kind")), value.get("reply"))
            return all(isinstance(v, str) for v in key) and key not in self._service_seen
        return False

    def _apply(self, event: dict) -> None:
        kind, value = event.get("kind"), event.get("value")
        if kind in ("http_game", "http_connect") and isinstance(value, dict):
            target = kind.removeprefix("http_")
            key = _stable(value)
            if key not in self._http_seen[target]:
                self._http_seen[target].add(key)
                (self.game_http if target == "game" else self.connect_http).append(value)
        elif kind == "http" and isinstance(value, dict):
            # Journals written by the first capture prototype did not carry a
            # target.  Preserve their conservative both-sides behavior when
            # resuming, but all newly written events are classified.
            key = _stable(value)
            for target, rows in (("game", self.game_http), ("connect", self.connect_http)):
                if key not in self._http_seen[target]:
                    self._http_seen[target].add(key)
                    rows.append(value)
        elif kind == "inventory" and isinstance(value, dict):
            key = _stable(value)
            if key not in self._inventory_seen:
                self._inventory_seen.add(key)
                self.inventory.append(value)
        elif kind == "issue" and isinstance(value, dict):
            key = _stable(value)
            if key not in self._issue_seen:
                self._issue_seen.add(key)
                self.issues.append(value)
        elif kind == "demux_client_version" and isinstance(value, int):
            self.demux["client_version"] = value
        elif kind == "demux_patch_info" and isinstance(value, str):
            self.demux["patch_info"] = value
        elif kind == "demux_service" and isinstance(value, dict):
            service, service_kind, reply = value.get("service"), str(value.get("service_kind")), value.get("reply")
            if not all(isinstance(v, str) for v in (service, service_kind, reply)):
                return
            key = (service, service_kind, reply)
            if key in self._service_seen:
                return
            self._service_seen.add(key)
            self.demux["services"].setdefault(service, {}).setdefault(service_kind, []).append(reply)

    def flush(self) -> None:
        _atomic_json(self.root / "fixtures.json", self.game_http)
        _atomic_json(self.root / "connect-fixtures.json", self.connect_http)
        _atomic_json(self.root / "inventory-updates.json", self.inventory)
        _atomic_json(self.root / "capture-issues.json", self.issues)
        # This collector does not decrypt NEX.  Preserve fixtures created by a
        # separate/manual recorder instead of silently erasing them on resume.
        _atomic_json(self.root / "fixtures-rmc.json", self.rmc)
        _atomic_json(self.root / "demux.json", self.demux)
        self._dirty_events = 0

    def close(self) -> dict:
        self.flush()
        report = self.report()
        _atomic_json(self.root / "capture-report.json", report, pretty=True)
        if not self._journal.closed:
            self._journal.close()
        return report

    def record_http(self, method: str, host: str, path: str, status: int, content_type: str,
                    body: bytes, *, request_body: bytes | None = None,
                    timestamp: float | None = None, target: str = "both") -> bool:
        """Record one decoded HTTP response; no request headers are accepted or stored.

        ``target`` is ``game``, ``connect``, or ``both``.  The network adapter
        derives it from the non-secret Ubi-AppId header and endpoint shape, then
        discards the header.  Keeping the two fixture sets separate matters:
        copying an allow-listed game reply into Connect's unkept marker pool can
        create a false privacy finding. Returns whether this response added a
        fixture, so adapters can report progress without exposing its URL.
        """
        if target not in ("game", "connect", "both"):
            raise ValueError("target must be 'game', 'connect', or 'both'")
        method, host = method.upper(), host.lower().rstrip(".")
        entry = {"method": method, "host": host, "path": path, "status": int(status),
                 "content_type": (content_type or "application/octet-stream").split(";", 1)[0].strip(),
                 "body_b64": base64.b64encode(body).decode("ascii")}
        targets = ("game", "connect") if target == "both" else (target,)
        added = False
        for selected in targets:
            added = self._event(f"http_{selected}", entry) or added

        match = INVENTORY_PATH.fullmatch(path.split("?", 1)[0])
        request, reply = _json_bytes(request_body or b""), _json_bytes(body)
        if method == "POST" and match and isinstance(request, dict) and isinstance(reply, dict):
            update = {"time": float(timestamp if timestamp is not None else time.time()),
                      "profileId": match.group(1), "request": request, "reply": reply}
            self._event("inventory", update)
        return added

    def record_issue(self, code: str, method: str, host: str, path: str, detail: str) -> None:
        """Persist a non-secret reason why a response could not be recorded."""
        issue = {"code": code, "method": method.upper(), "host": host.lower().rstrip("."),
                 "path": path.split("?", 1)[0], "detail": detail}
        self._event("issue", issue)

    def feed_demux(self, flow_id: str, from_client: bool, chunk: bytes) -> None:
        """Feed one arbitrary plaintext chunk from a generic-TCP TLS interception."""
        stream = self._streams.setdefault(str(flow_id), _DemuxStream())
        buf = stream.client if from_client else stream.server
        buf.extend(chunk)
        while len(buf) >= 4:
            size = int.from_bytes(buf[:4], "big")
            if size > MAX_DEMUX_MESSAGE:
                # The adapter selected the wrong TCP flow or the stream is corrupt.
                buf.clear()
                return
            if len(buf) < 4 + size:
                return
            message = bytes(buf[4:4 + size])
            del buf[:4 + size]
            try:
                self._demux_message(stream, from_client, message)
            except (pb.DecodeError, TypeError, ValueError):
                # Recording must never modify or terminate the proxied connection.
                continue

    def record_tcp(self, flow_id: str, from_client: bool, chunk: bytes) -> None:
        """Adapter-friendly alias for :meth:`feed_demux`."""
        self.feed_demux(flow_id, from_client, chunk)

    def end_demux(self, flow_id: str) -> None:
        self._streams.pop(str(flow_id), None)

    def _demux_message(self, stream: _DemuxStream, from_client: bool, message: bytes) -> None:
        outer = pb.decode(message)
        request_or_response, push = pb.first(outer, 1), pb.first(outer, 2)
        if isinstance(request_or_response, bytes):
            envelope = pb.decode(request_or_response)
            request_id = pb.first(envelope, 1)
            field = next((f for f in envelope if f[0] != 1), None)
            if field is not None and isinstance(request_id, int):
                number, raw = field[0], field[1]
                body = pb.try_decode(raw) if isinstance(raw, bytes) else None
                if from_client and number == 3 and body is not None:
                    stream.opening[request_id] = pb.text(body, 2)
                elif not from_client and number == 3 and body is not None:
                    service = stream.opening.pop(request_id, "")
                    channel, ok = pb.first(body, 1), pb.first(body, 2)
                    if service and isinstance(channel, int) and ok:
                        stream.channels[channel] = service
                elif not from_client and number == 5 and isinstance(raw, bytes):
                    self._event("demux_patch_info", base64.b64encode(raw).decode("ascii"))
        if not isinstance(push, bytes):
            return
        for number, raw, _ in pb.decode(push):
            body = pb.try_decode(raw) if isinstance(raw, bytes) else None
            if body is None:
                continue
            if from_client and number == 4:
                version = pb.first(body, 1)
                if isinstance(version, int):
                    self._event("demux_client_version", version)
            elif number == 2:
                channel = pb.first(body, 1)
                if isinstance(channel, int):
                    stream.channels.pop(channel, None)
            elif not from_client and number == 1:
                channel, framed = pb.first(body, 1), pb.first(body, 2)
                service = stream.channels.get(channel) if isinstance(channel, int) else None
                if not service or not isinstance(framed, bytes):
                    continue
                inner = pb.unframe(framed)
                service_kind = _kind(inner)
                if service_kind is None:
                    continue
                self._event("demux_service", {
                    "service": service, "service_kind": str(service_kind),
                    "reply": base64.b64encode(inner).decode("ascii"),
                })

    def report(self) -> dict:
        offers: dict[str, dict] = {}
        actions: set[str] = set()
        families: dict[tuple, dict] = {}
        allowed = {name: False for name in REQUIRED_GAME_ENDPOINTS}
        achievement_zip = False
        for entry in self.game_http:
            method, raw_path = entry.get("method"), entry.get("path", "")
            path = raw_path.split("?", 1)[0]
            try:
                successful = 200 <= int(entry.get("status", 0)) < 300
            except (TypeError, ValueError):
                successful = False
            for name, expected_path in REQUIRED_GAME_ENDPOINTS.items():
                if successful and method == "GET" and path == expected_path:
                    allowed[name] = True
            try:
                body = json.loads(base64.b64decode(entry.get("body_b64", ""), validate=True))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                body = None
            if successful and method == "GET" and OFFERS_PATH.fullmatch(path) and isinstance(body, dict):
                rows = body.get("offers") if isinstance(body.get("offers"), list) else []
                for offer in rows:
                    if isinstance(offer, dict) and "offerId" in offer:
                        offers.setdefault(str(offer["offerId"]), offer)
                query = parse_qsl(urlsplit(raw_path).query, keep_blank_values=True)
                family = tuple(sorted((k, v) for k, v in query if k not in ("offset", "limit")))
                values = dict(query)
                try:
                    offset = int(values.get("offset", 0))
                    limit = int(values["limit"]) if "limit" in values else None
                except ValueError:
                    offset, limit = 0, None
                state = families.setdefault(family, {"pages": {}, "limits": set()})
                state["pages"][offset] = len(rows)
                if limit and limit > 0:
                    state["limits"].add(limit)
            if successful and method == "GET" and ACTIONS_PATH.fullmatch(path) and isinstance(body, dict):
                for action in body.get("actions", []):
                    if isinstance(action, dict) and "id" in action:
                        actions.add(str(action["id"]))
        for entry in self.connect_http:
            path = entry.get("path", "").split("?", 1)[0]
            if entry.get("method") != "GET" or not ACHIEVEMENT_ZIP.fullmatch(path) \
                    or entry.get("status") != 200:
                continue
            try:
                achievement_zip = achievement_zip or base64.b64decode(
                    entry.get("body_b64", ""), validate=True).startswith(b"PK")
            except (binascii.Error, ValueError):
                pass

        family_report = []
        for family, state in sorted(families.items(), key=lambda x: x[0]):
            pages, limits = state["pages"], state["limits"]
            limit = next(iter(limits)) if len(limits) == 1 else None
            terminal_offsets = [off for off, count in pages.items() if count == 0 or limit and count < limit]
            terminal = bool(terminal_offsets)
            contiguous = False
            if limit and terminal:
                end = min(terminal_offsets)
                contiguous = all(offset in pages for offset in range(0, end + 1, limit))
            family_report.append({
                "query": urlencode(family), "offsets": sorted(pages), "page_counts": pages,
                "limit": limit, "terminal": terminal, "contiguous": contiguous,
            })

        warnings = []
        if not self.game_http:
            warnings.append("no HTTP responses were recorded")
        if not offers:
            warnings.append("no store offers were recorded")
        elif len(offers) < EXPECTED_OFFERS:
            warnings.append(f"only {len(offers)} unique offers were recorded; historical complete captures had "
                            f"at least {EXPECTED_OFFERS}")
        if not actions:
            warnings.append("no Ubisoft Club actions were recorded")
        for name, present in allowed.items():
            if not present:
                warnings.append(f"missing game-wide endpoint: {name} ({REQUIRED_GAME_ENDPOINTS[name]})")
        for family in family_report:
            if not family["terminal"] or not family["contiguous"]:
                warnings.append(f"offer pagination is incomplete for query family: {family['query'] or '(unfiltered)'}")
        if not achievement_zip:
            warnings.append("achievement definitions ZIP was not recorded")
        ownership = len(self.demux.get("services", {}).get("ownership_service", {}).get("2", []))
        if not ownership:
            warnings.append("Ubisoft Connect ownership_service kind 2 was not recorded; built-in products will be used")
        for issue in self.issues:
            warnings.append(f"skipped response ({issue.get('code')}): {issue.get('method')} "
                            f"{issue.get('host')}{issue.get('path')} ({issue.get('detail')})")
        pagination_complete = bool(family_report) and all(
            family["terminal"] and family["contiguous"] for family in family_report)
        required_present = all(allowed.values())
        semantic_complete = bool(len(offers) >= EXPECTED_OFFERS and actions and achievement_zip and pagination_complete
                                 and required_present and not self.issues)
        return {
            "http_responses": len({_stable(e) for e in self.game_http + self.connect_http}),
            "http_by_target": {"game": len(self.game_http), "connect": len(self.connect_http)},
            "unique_offers": len(offers),
            "unique_actions": len(actions), "offer_families": family_report,
            "game_endpoints": allowed, "achievement_zip": achievement_zip,
            "demux": {"client_version": self.demux.get("client_version"),
                      "patch_info": bool(self.demux.get("patch_info")),
                      "ownership_replies": ownership},
            "skipped_responses": self.issues,
            # A skipped body may have contained an identifying value that the
            # pack privacy check needs as a marker. The builder can still be
            # run for diagnosis, but the capture must not be presented as ready.
            "ready_for_pack_build": bool(self.game_http and not self.issues),
            "semantic_complete": semantic_complete,
            "warnings": warnings,
        }


def main(argv: list[str] | None = None) -> int:
    """Replay the crash journal and finalize canonical files/report."""
    parser = argparse.ArgumentParser(description="finalize Powder capture recordings")
    parser.add_argument("recordings", type=Path)
    args = parser.parse_args(argv)
    store = RecordingStore(args.recordings)
    report = store.close()
    print(f"capture finalized: {report['http_responses']} HTTP replies, "
          f"{report['unique_offers']} offers, {len(report['warnings'])} warning(s)")
    for warning in report["warnings"]:
        print("  " + warning)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
