"""mitmproxy adapter for Powder's private game-data recording format.

Run this only through ``capture.ps1``.  The adapter deliberately persists response
bodies, but never request headers, cookies, authorization values, or passwords.
The recordings still contain personal response data and must remain private.

HTTP is handled by mitmproxy.  Ubisoft Connect's demux protocol is TLS followed
by length-prefixed protobuf messages, so mitmproxy exposes it as a generic TCP
flow and :class:`RecordingStore` reconstructs its frames across arbitrary chunks.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path

# ``uvx mitmdump -s tools/capture/addon.py`` puts this directory, not the
# repository root, on sys.path.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mitmproxy import connection, ctx, http, tcp  # type: ignore[import-not-found]  # provided by mitmdump

from powder.server.hostnames import DEMUX_HOST, REDIRECT_HOSTS
from tools.capture.recorder import RecordingStore, classify_http, normalize_host, request_http_host

DEFAULT_MAX_BODY = 32 * 1024 * 1024
HTTP_HOSTS = frozenset(h.lower() for h in REDIRECT_HOSTS if h != DEMUX_HOST)
INVENTORY_UPDATE = re.compile(r"^/v1/profiles/[^/?]+/inventory(?:\?|$)")
SHUTDOWN_POLL_SECONDS = 0.2


def _write_ready_sentinel(path: Path) -> None:
    """Atomically publish that this addon reached mitmproxy's running hook."""
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8", newline="\n") as f:
        f.write("ready\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def _tcp_host(flow: tcp.TCPFlow) -> str:
    """Best available original host for a generic TLS-over-TCP flow."""
    for conn in (flow.server_conn, flow.client_conn):
        value = getattr(conn, "sni", None)
        if value:
            return normalize_host(value)
    address = getattr(flow.server_conn, "address", None)
    if isinstance(address, tuple) and address:
        return normalize_host(str(address[0]))
    return ""


def _target(flow: http.HTTPFlow, host: str) -> str:
    """Classify without persisting the request header used to make the choice.

    The game and Connect share hosts, but identify themselves with Ubi-AppId.
    Missing-header requests are classified by the builder's endpoint allow-lists;
    ambiguous personal endpoints go to both marker pools. Blindly duplicating an
    allow-listed reply would make it unkept on the other side and can turn a
    generic config value into a false privacy marker.
    """
    return classify_http(flow.request.method, host, flow.request.path,
                         flow.request.headers.get("Ubi-AppId", ""))


def _record_issue(store: RecordingStore, code: str, flow: http.HTTPFlow, host: str, detail: str) -> None:
    try:
        store.record_issue(code, flow.request.method, host, flow.request.path, detail)
    except Exception as exc:
        ctx.log.error(f"Powder capture could not persist a skipped-response warning: {type(exc).__name__}")


class PowderCaptureAddon:
    def __init__(self) -> None:
        self.store: RecordingStore | None = None
        self.root: Path | None = None
        self.shutdown_watcher: asyncio.Task[None] | None = None
        self.redirected_connections = 0
        self.http_requests = 0
        self.target_requests = 0
        self.saved_responses = 0

    def load(self, loader) -> None:
        loader.add_option(
            "powder_recordings",
            str,
            "",
            "Private output directory for Powder recording JSON files.",
        )
        loader.add_option(
            "powder_max_body",
            int,
            DEFAULT_MAX_BODY,
            "Largest decoded HTTP response body to retain, in bytes.",
        )
        loader.add_option(
            "powder_shutdown_file",
            str,
            "",
            "Private sentinel path used by capture.ps1 to request a graceful shutdown.",
        )
        loader.add_option(
            "powder_ready_file",
            str,
            "",
            "Per-run sentinel path used by capture.ps1 to confirm startup completed.",
        )

    def configure(self, updated: set[str]) -> None:
        if "powder_recordings" not in updated:
            return
        configured = str(ctx.options.powder_recordings or "").strip()
        if not configured:
            if self.store is not None:
                self.store.close()
            self.store = None
            self.root = None
            return
        root = Path(configured).expanduser().resolve()
        if root == self.root and self.store is not None:
            return
        if self.store is not None:
            self.store.close()
        self.store = RecordingStore(root)
        self.root = root
        ctx.log.info(f"Powder capture is writing private recordings under {root}")

    def running(self) -> None:
        # ``configure`` normally opens the store.  Keeping this fallback makes
        # direct addon use robust across mitmproxy lifecycle changes.
        if self.store is None and str(ctx.options.powder_recordings or "").strip():
            self.configure({"powder_recordings"})
        configured = str(ctx.options.powder_shutdown_file or "").strip()
        if configured and self.shutdown_watcher is None:
            sentinel = Path(configured).expanduser().resolve()
            self.shutdown_watcher = asyncio.create_task(
                self._watch_for_shutdown(sentinel), name="powder-capture-shutdown"
            )
        ready_configured = str(ctx.options.powder_ready_file or "").strip()
        if ready_configured:
            if self.store is None:
                raise RuntimeError("Powder capture cannot become ready without an open recording store")
            _write_ready_sentinel(Path(ready_configured).expanduser().resolve())
            ctx.log.info("Powder capture addon and local redirector are ready.")

    async def _watch_for_shutdown(self, sentinel: Path) -> None:
        try:
            while not sentinel.is_file():
                await asyncio.sleep(SHUTDOWN_POLL_SECONDS)
        except asyncio.CancelledError:
            return
        except OSError as exc:
            ctx.log.error(f"Powder capture could not watch its shutdown sentinel: {type(exc).__name__}")
            return
        ctx.log.info("Powder capture received a graceful shutdown request; finalizing recordings.")
        ctx.master.shutdown()

    def client_connected(self, client: connection.Client) -> None:
        self.redirected_connections += 1
        if self.redirected_connections == 1:
            # Do not log peer addresses or process metadata. This line only proves that the
            # local redirector selected at least one connection from the requested process.
            ctx.log.info("Powder capture observed its first redirected client connection.")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        self.http_requests += 1
        if self.http_requests == 1:
            ctx.log.info("Powder capture decoded its first redirected HTTP request.")
        if request_http_host(flow.request) in HTTP_HOSTS:
            self.target_requests += 1
            if self.target_requests == 1:
                ctx.log.info("Powder capture matched its first pack-host HTTP request.")

    def response(self, flow: http.HTTPFlow) -> None:
        store = self.store
        if store is None or flow.response is None:
            return
        host = request_http_host(flow.request)
        if host not in HTTP_HOSTS:
            return
        try:
            body = flow.response.get_content(strict=True) or b""
        except Exception as exc:  # malformed third-party encodings must not stop the capture
            _record_issue(store, "decode-failed", flow, host, type(exc).__name__)
            ctx.log.warning(f"Powder capture could not decode a response from {host}: {type(exc).__name__}")
            return
        maximum = max(0, int(ctx.options.powder_max_body))
        if len(body) > maximum:
            base_path = flow.request.path.split("?", 1)[0]
            _record_issue(store, "body-too-large", flow, host, f"{len(body)} bytes exceeds {maximum}")
            ctx.log.warning(
                f"Powder capture skipped oversized response {flow.request.method} "
                f"{host}{base_path} ({len(body)} bytes; limit {maximum})"
            )
            return

        request_body = None
        if flow.request.method.upper() == "POST" and INVENTORY_UPDATE.match(flow.request.path):
            try:
                request_body = flow.request.get_content(strict=True) or b""
            except Exception:
                # The response remains valuable even if the optional progress
                # import record cannot be reconstructed.
                request_body = None

        content_type = flow.response.headers.get("content-type", "").split(";", 1)[0].strip()
        timestamp = flow.response.timestamp_end or flow.response.timestamp_start
        try:
            target = _target(flow, host)
            added = store.record_http(
                method=flow.request.method.upper(),
                host=host,
                path=flow.request.path,
                status=flow.response.status_code,
                content_type=content_type,
                body=body,
                request_body=request_body,
                timestamp=timestamp,
                target=target,
            )
            if added:
                self.saved_responses += 1
                # Deliberately omit method, host, path, headers, and body. Paths can contain
                # account IDs and query strings can contain session data.
                ctx.log.info(
                    "Powder capture saved a new "
                    f"{target} HTTP response (status {flow.response.status_code}; "
                    f"totals: {len(store.game_http)} game, {len(store.connect_http)} Connect)."
                )
        except Exception as exc:
            # An output-disk failure must be visible, but must not alter the
            # official response being relayed to the game.
            ctx.log.error(f"Powder capture could not persist a response: {type(exc).__name__}")

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        store = self.store
        if store is None or _tcp_host(flow) != DEMUX_HOST or not flow.messages:
            return
        message = flow.messages[-1]
        try:
            store.record_tcp(str(flow.id), bool(message.from_client), bytes(message.content))
        except Exception as exc:
            ctx.log.error(f"Powder capture could not persist demux data: {type(exc).__name__}")

    def tcp_end(self, flow: tcp.TCPFlow) -> None:
        if self.store is not None:
            self.store.end_demux(str(flow.id))

    def tcp_error(self, flow: tcp.TCPFlow) -> None:
        if self.store is not None:
            self.store.end_demux(str(flow.id))

    def done(self) -> None:
        if self.shutdown_watcher is not None and not self.shutdown_watcher.done():
            self.shutdown_watcher.cancel()
        self.shutdown_watcher = None
        ctx.log.info(
            "Powder capture transport summary: "
            f"{self.redirected_connections} redirected connection(s), "
            f"{self.http_requests} HTTP request(s), "
            f"{self.target_requests} pack-host request(s), "
            f"{self.saved_responses} new saved response(s)."
        )
        if self.store is not None:
            self.store.close()
            self.store = None


addons = [PowderCaptureAddon()]
