"""Privacy check for a game-data pack: nothing that identifies a person may end up in it.

Markers are collected from the *personal* parts of the source recordings (everything the builder did not
allow-list): the values of identifying JSON keys (profile/user ids, names, emails, tickets, ip), every
GUID in friend lists, profile lookups and leaderboards, and Connect's friends. Then every file of the pack
(including base64 bodies, decoded) is searched for them. Any hit fails the check.
"""
from __future__ import annotations

import base64
import io
import json
import re
import zlib
import zipfile
from pathlib import Path

from ..transport.demux import pb

GUID = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
IDENTIFYING_KEYS = {"profileid", "userid", "idonplatform", "nameonplatform", "username", "email",
                    "emailaddress", "ticket", "sessionkey", "sessionid", "remembermeticket", "clientip",
                    "firstname", "lastname", "dateofbirth", "friendid", "pid"}
# replies that are lists of people: every GUID in them is a marker. (Rider cards and inventories are not
# here: they also hold game item ids that legitimately appear in the store catalogue; their owner is
# caught through the profileId key.)
PEOPLE_PATHS = re.compile(r"/friends|/v3/profiles$|/onlineStatuses|/blocks|harboursocial")
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 512
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024


class ArchivePrivacyError(ValueError):
    pass


def _walk(value, out: set[str]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if k.lower() in IDENTIFYING_KEYS and isinstance(v, (str, int)) and len(str(v)) >= 6:
                out.add(str(v))
            _walk(v, out)
    elif isinstance(value, list):
        for v in value:
            _walk(v, out)


def markers_from_http(entries: list[dict], kept: set[int]) -> set[str]:
    """Markers from recorded HTTPS replies that were NOT copied into the pack (`kept` = their indexes)."""
    out: set[str] = set()
    for i, e in enumerate(entries):
        if i in kept:
            continue
        body = base64.b64decode(e.get("body_b64", ""))
        try:
            _walk(json.loads(body), out)
        except (ValueError, UnicodeDecodeError):
            pass
        if PEOPLE_PATHS.search(e["path"]):
            out.update(g.decode().lower() for g in GUID.findall(body))
    return out


def markers_from_rmc(rmc: dict, kept: set[str]) -> set[str]:
    """Every GUID in NEX replies that were not kept (leaderboards, profiles, matchmaking)."""
    out: set[str] = set()
    for method, rows in rmc.items():
        if method in kept:
            continue
        for row in rows:
            out.update(g.decode().lower() for g in GUID.findall(bytes.fromhex(row.get("body", ""))))
    return out


def _friend_names(raw: bytes) -> set[str]:
    """Names in a friends_service initialize reply: {1: {1 id, 22: {2: {2: {1 profile id, 2 name}}...}}}."""
    names = set()
    try:
        body = pb.decode(pb.first(pb.decode(pb.first(pb.decode(raw), 1)), 22) or b"")
    except (pb.DecodeError, TypeError):
        return names
    for n, entry, _ in body:
        if n == 2 and isinstance(entry, bytes):
            inner = pb.try_decode(pb.first(pb.try_decode(entry) or [], 2) or b"") or []
            name = pb.first(inner, 2)
            if isinstance(name, bytes) and len(name) >= 4:
                names.add(name.decode("utf-8", "replace"))
    return names


def markers_from_demux(demux: dict) -> set[str]:
    """Friends (ids, names) and the player's id from Connect's demux replies."""
    out: set[str] = set()
    for svc, kinds in demux.get("services", {}).items():
        if svc == "ownership_service":
            continue                                   # product data, handled by the allow-list
        for kind, replies in kinds.items():
            for b64 in replies:
                raw = base64.b64decode(b64)
                out.update(g.decode().lower() for g in GUID.findall(raw))
                if svc == "friends_service" and kind == "22":
                    out.update(_friend_names(raw))
    return out


def _pack_blobs(root: Path):
    for path in sorted(root.rglob("*.json")):
        raw = path.read_bytes()
        yield path.relative_to(root).as_posix(), raw
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        for b in _b64_strings(data):
            name = f"{path.relative_to(root).as_posix()} (decoded)"
            yield name, b
            yield from _archive_members(name, b)


def _archive_members(source: str, blob: bytes):
    """Yield bounded decompressed members so privacy markers cannot hide in a ZIP body."""
    if not blob.startswith(b"PK"):
        return
    if len(blob) > MAX_ARCHIVE_BYTES:
        raise ArchivePrivacyError(f"{source}: embedded ZIP exceeds the privacy-check limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise ArchivePrivacyError(f"{source}: embedded ZIP is malformed") from exc
    try:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ArchivePrivacyError(f"{source}: embedded ZIP entry count is outside the privacy-check limit")
        if sum(max(0, info.file_size) for info in infos) > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ArchivePrivacyError(f"{source}: embedded ZIP expands beyond the privacy-check limit")
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 1 or info.file_size < 0 or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ArchivePrivacyError(f"{source}: embedded ZIP member is unsafe to inspect")
            try:
                raw = archive.read(info)
            except (OSError, RuntimeError, NotImplementedError, zlib.error, zipfile.BadZipFile) as exc:
                raise ArchivePrivacyError(f"{source}: embedded ZIP member failed validation") from exc
            if len(raw) != info.file_size:
                raise ArchivePrivacyError(f"{source}: embedded ZIP member changed while reading")
            # Member names can themselves contain untrusted/account text, so keep diagnostics generic.
            yield f"{source} (ZIP member)", raw
    finally:
        archive.close()


def _b64_strings(value):
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, str) and (k.endswith("b64") or k in ("patch_info",)):
                yield base64.b64decode(v)
            else:
                yield from _b64_strings(v)
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, str) and len(v) > 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", v):
                try:
                    yield base64.b64decode(v)
                except ValueError:
                    pass
            else:
                yield from _b64_strings(v)


def check(root: Path, markers: set[str], allowed: set[str] = frozenset()) -> list[str]:
    """-> findings 'file: marker' (empty = clean). `allowed` = markers known to be game-wide (e.g. the
    game's own app/space ids, which also appear inside personal replies)."""
    needles = [(m, m.encode()) for m in markers - set(allowed) if len(m) >= 6]
    lowered = [(m, n.lower()) for m, n in needles]
    findings = []
    try:
        for name, blob in _pack_blobs(root):
            low = blob.lower()
            for m, n in lowered:
                if n in low:
                    findings.append(f"{name}: {m[:12]}...")
    except ArchivePrivacyError as exc:
        findings.append(str(exc))
    return sorted(set(findings))
