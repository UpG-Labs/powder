import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from powder.server.constants import APP_ID, CONNECT_APP_ID, SPACE_ID
from powder.server.gamedata.build import _products, build
from powder.server.transport.demux import pb
from tools.capture.recorder import RecordingStore, classify_http, request_http_host


HOST = "public-ubiservices.ubi.com"
PLAYER = "00000000-0000-4000-8000-000000000001"


def test_windows_runner_avoids_unproxyable_connect_transports():
    runner = Path(__file__).parents[1] / "tools" / "capture" / "capture.ps1"
    script = runner.read_text(encoding="utf-8")
    assert '"Steep.exe"' in script and '"steep.exe"' in script and '"STEEP.EXE"' in script
    assert '$CaptureProcessNames = @($ConnectUiProcessNames)' in script
    assert '$demuxPassthroughPattern = "^" + [regex]::Escape($DemuxHost) + "(?::443)?$"' in script
    assert '"--ignore-hosts", (Quote-ProcessArgument $demuxPassthroughPattern)' in script
    assert '$interceptionArguments += @(' in script
    assert '$mitmArguments += $interceptionArguments' in script
    assert '"--set", "http3=false"' in script
    assert '"--allow-hosts", (Quote-ProcessArgument $allowedHostsPattern)' in script
    assert '$CaptureHosts = @($RedirectHosts | Where-Object { $_ -ne $DemuxHost })' in script
    assert '$mode = "local:" + ($CaptureProcessNames -join ",")' in script
    assert '$mode = "local:" + ($StoppedProcessNames -join ",")' not in script
    assert '"--tcp-hosts"' not in script

    optional_start = script.index("    if ($CaptureConnectUi) {", script.index("$interceptionArguments = @("))
    arguments_start = script.index("    $mitmArguments = @(", optional_start)
    optional_block = script[optional_start:arguments_start]
    assert '"--allow-hosts"' in optional_block and '"http3=false"' in optional_block
    base_arguments = script[arguments_start:script.index("$mitmArguments += $interceptionArguments")]
    assert '"--allow-hosts"' not in base_arguments and '"http3=false"' not in base_arguments


def test_windows_runner_does_not_abort_cleanup_on_taskkill_race():
    runner = Path(__file__).parents[1] / "tools" / "capture" / "capture.ps1"
    script = runner.read_text(encoding="utf-8")
    assert "try {\n        & taskkill.exe /PID $processId /T /F" in script
    assert 'catch {\n        $taskkillSucceeded = $false' in script
    assert "return $taskkillSucceeded -and $rootStopped" in script


def test_windows_runner_requests_graceful_mitmdump_shutdown():
    root = Path(__file__).parents[1]
    runner = (root / "tools" / "capture" / "capture.ps1").read_text(encoding="utf-8")
    addon = (root / "tools" / "capture" / "addon.py").read_text(encoding="utf-8")
    assert '"powder_shutdown_file=$shutdownFile"' in runner
    assert runner.count("Request-MitmdumpShutdown") >= 3  # definition, recovery, ordinary shutdown
    assert 'Stop-RecordedProcess $state.mitmproxy "mitmproxy" 15000' in runner
    assert '"powder_shutdown_file"' in addon
    assert "ctx.master.shutdown()" in addon


def test_windows_runner_waits_before_reading_child_exit_codes():
    runner = Path(__file__).parents[1] / "tools" / "capture" / "capture.ps1"
    script = runner.read_text(encoding="utf-8")
    assert script.count("$mitmProcess.WaitForExit()") == 3
    assert script.count("$mitmExitCode = $mitmProcess.ExitCode") == 3
    assert "$attachProcess.WaitForExit()\n                $attachExitCode = $attachProcess.ExitCode" in script
    assert "$($attachProcess.ExitCode)" not in script


def test_windows_runner_uses_a_current_run_ready_sentinel():
    root = Path(__file__).parents[1]
    runner = (root / "tools" / "capture" / "capture.ps1").read_text(encoding="utf-8")
    addon = (root / "tools" / "capture" / "addon.py").read_text(encoding="utf-8")

    assert '$readyFile = Join-Path $confDir $ReadyFileName' in runner
    assert '"powder_ready_file=$readyFile"' in runner
    assert '-not (Test-Path -LiteralPath $readyFile -PathType Leaf)' in runner
    assert "$recorderJournal" not in runner
    assert '"powder_ready_file"' in addon
    assert "os.replace(temporary, path)" in addon

    running = addon.index("    def running(self) -> None:")
    watcher = addon.index("self.shutdown_watcher = asyncio.create_task", running)
    publish = addon.index("_write_ready_sentinel(", watcher)
    assert watcher < publish

    wait = runner.index("    while (-not (Test-Path -LiteralPath $caCertificate")
    trust = runner.index("    $thumbprint = Get-CertificateThumbprint", wait)
    between = runner[wait:trust]
    assert between.count("$mitmProcess.Refresh()") == 2
    assert "if ($mitmProcess.HasExited)" in between


def test_windows_cleanup_binds_state_before_any_recovery_mutation():
    runner = Path(__file__).parents[1] / "tools" / "capture" / "capture.ps1"
    script = runner.read_text(encoding="utf-8")
    start = script.index("function Invoke-RecoveryCleanup")
    end = script.index("function Assert-NoRedirectedHosts", start)
    recovery = script[start:end]
    first_mutation = recovery.index("$attachStopped = Stop-RecordedProcess")

    for guard in (
        '$requiredStateProperties = @("format", "recordings", "confdir", "ca_thumbprint", "attach", "mitmproxy")',
        "$validFormatType = $state.format -is [int] -or $state.format -is [long]",
        "$recordedRecordings = Get-CanonicalRecoveryPath $state.recordings",
        "$recordedConfDir = Get-CanonicalRecoveryPath $state.confdir",
        '$thumbprint -notmatch "^[0-9A-Fa-f]{40}$"',
        "$certificateThumbprint = Get-CertificateThumbprint $caFile",
        "$thumbprint.ToUpperInvariant() -ne $certificateThumbprint",
    ):
        assert recovery.index(guard) < first_mutation
    assert recovery.index("Remove-CaptureCertificate $thumbprint") > first_mutation


def test_addon_reports_privacy_safe_capture_stages():
    addon = (Path(__file__).parents[1] / "tools" / "capture" / "addon.py").read_text(encoding="utf-8")
    assert "first redirected client connection" in addon
    assert "first redirected HTTP request" in addon
    assert "first pack-host HTTP request" in addon
    assert "Powder capture transport summary" in addon


def test_addon_uses_http_authority_in_local_transparent_mode():
    # Local capture's transparent HTTP layer exposes the original destination IP
    # as Request.host. Request.pretty_host recovers Host/:authority after TLS.
    request = SimpleNamespace(host="203.132.26.96", pretty_host=f"{HOST}.")
    assert request_http_host(request) == HOST

    # Keep a safe fallback for request-like objects without mitmproxy's helper.
    assert request_http_host(SimpleNamespace(host=f"{HOST}:443")) == HOST

    addon = (Path(__file__).parents[1] / "tools" / "capture" / "addon.py").read_text(encoding="utf-8")
    assert addon.count("request_http_host(flow.request)") == 2
    assert "_host(flow.request.host)" not in addon


def _body(value):
    return json.dumps(value).encode()


def test_http_classification_does_not_retain_or_require_headers():
    config = f"/v2/applications/{APP_ID}/configuration"
    events = f"/v4/spaces/{SPACE_ID}/configs/events"
    assert classify_http("GET", HOST, "/anything", APP_ID) == "game"
    assert classify_http("GET", HOST, config, CONNECT_APP_ID) == "connect"
    assert classify_http("GET", HOST, config) == "game"
    assert classify_http("GET", "static3.cdn.ubi.com",
                         "/orbit/uplay_launcher_3_0/assets/0123abcd.zip") == "connect"
    assert classify_http("GET", HOST, events) == "both"       # copied because both sides allow-list it
    assert classify_http("POST", HOST, "/v3/profiles/sessions") == "both"  # marker source


def test_http_recording_inventory_resume_and_completeness(tmp_path):
    root = tmp_path / "recordings"
    store = RecordingStore(root)
    store.record_http("GET", HOST, f"/v2/applications/{APP_ID}/configuration", 200,
                      "application/json; charset=utf-8", _body({"configuration": {}}), target="game")
    store.record_http("GET", HOST, f"/v1/spaces/{SPACE_ID}/offers?tags=SKI&offset=0&limit=2", 200,
                      "application/json", _body({"offers": [{"offerId": "a"}, {"offerId": "b"}]}),
                      target="game")
    store.record_http("GET", HOST, f"/v1/spaces/{SPACE_ID}/offers?tags=SKI&offset=2&limit=2", 200,
                      "application/json", _body({"offers": [{"offerId": "c"}]}), target="game")
    store.record_http("GET", HOST, f"/v1/profiles/{PLAYER}/actions?spaceId={SPACE_ID}", 200,
                      "application/json", _body({"actions": [{"id": "action-1", "profileId": PLAYER}]}),
                      target="game")
    request = {"spaceId": SPACE_ID, "offerId": "a", "offerRevision": 1}
    reply = {"items": [{"itemId": "x", "quantity": 1}], "transactionId": "tx"}
    store.record_http("POST", HOST, f"/v1/profiles/{PLAYER}/inventory", 200, "application/json",
                      _body(reply), request_body=_body(request), timestamp=123.5, target="game")
    report = store.close()

    game = json.loads((root / "fixtures.json").read_text())
    connect = json.loads((root / "connect-fixtures.json").read_text())
    assert len(game) == 5 and connect == []
    assert set(game[0]) == {"method", "host", "path", "status", "content_type", "body_b64"}
    assert base64.b64decode(game[0]["body_b64"]) == _body({"configuration": {}})
    assert game[0]["content_type"] == "application/json"
    updates = json.loads((root / "inventory-updates.json").read_text())
    assert updates == [{"time": 123.5, "profileId": PLAYER, "request": request, "reply": reply}]
    assert report["unique_offers"] == 3 and report["unique_actions"] == 1
    assert report["offer_families"][0]["terminal"]
    assert report["offer_families"][0]["contiguous"]

    # Canonical files plus the journal can both be replayed without duplication.
    resumed = RecordingStore(root)
    resumed.record_http("GET", HOST, f"/v2/applications/{APP_ID}/configuration", 200,
                        "application/json", _body({"configuration": {}}), target="game")
    resumed.close()
    assert len(json.loads((root / "fixtures.json").read_text())) == 5
    pack = tmp_path / "gamedata"
    build_report = build(root, pack)
    assert not build_report.findings
    assert (pack / "MANIFEST.json").is_file()


def test_http_recording_reports_only_new_fixtures_across_resume(tmp_path):
    root = tmp_path / "recordings"
    store = RecordingStore(root)
    args = ("GET", HOST, "/private/profile/path?ticket=secret", 200, "application/json", b"{}")
    assert store.record_http(*args, target="game")
    assert not store.record_http(*args, target="game")
    store.close()

    resumed = RecordingStore(root)
    assert not resumed.record_http(*args, target="game")
    assert resumed.record_http(*args, target="connect")
    assert not resumed.record_http(*args, target="both")
    resumed.close()


def test_demux_chunk_reassembly_channel_correlation_and_service_reply(tmp_path):
    root = tmp_path / "recordings"
    store = RecordingStore(root)

    open_request = pb.frame(pb.encode([(1, [(1, 7), (3, [(2, "ownership_service")])])]))
    version = pb.frame(pb.encode([(2, [(4, [(1, 13368)])])]))
    open_reply = pb.frame(pb.encode([(1, [(1, 7), (3, [(1, 42), (2, 1)])])]))
    patch_body = pb.encode([(1, 1), (5, 13368)])
    patch_reply = pb.frame(pb.encode([(1, [(1, 8), (5, patch_body)])]))
    inner = pb.encode([(1, [(1, 9), (2, [(1, 1), (2, b"products")])])])
    service_reply = pb.frame(pb.encode([(2, [(1, [(1, 42), (2, pb.frame(inner))])])]))

    # TCP chunks are intentionally split and coalesced at arbitrary boundaries.
    store.feed_demux("flow", True, open_request[:3])
    store.feed_demux("flow", True, open_request[3:] + version)
    store.feed_demux("flow", False, open_reply + patch_reply[:5])
    store.feed_demux("flow", False, patch_reply[5:] + service_reply)
    store.end_demux("flow")
    report = store.close()

    demux = json.loads((root / "demux.json").read_text())
    assert demux["client_version"] == 13368
    assert base64.b64decode(demux["patch_info"]) == patch_body
    assert [base64.b64decode(x) for x in demux["services"]["ownership_service"]["2"]] == [inner]
    assert report["demux"]["ownership_replies"] == 1


def test_incomplete_offer_page_is_reported(tmp_path):
    store = RecordingStore(tmp_path / "recordings")
    store.record_http("GET", HOST, f"/v1/spaces/{SPACE_ID}/offers?offset=0&limit=2", 200,
                      "application/json", _body({"offers": [{"offerId": "a"}, {"offerId": "b"}]}),
                      target="game")
    report = store.close()
    assert not report["offer_families"][0]["terminal"]
    assert any("pagination is incomplete" in warning for warning in report["warnings"])


def test_truncated_journal_tail_is_repaired_before_resume(tmp_path):
    root = tmp_path / "recordings"
    store = RecordingStore(root)
    store.record_http("GET", HOST, "/one", 200, "application/json", b"{}")
    store.close()
    with (root / "capture-journal.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"kind":"http","value":')

    resumed = RecordingStore(root)
    resumed.record_http("GET", HOST, "/two", 200, "application/json", b"{}")
    resumed.close()
    assert [entry["path"] for entry in json.loads((root / "fixtures.json").read_text())] == ["/one", "/two"]
    assert all(json.loads(line) for line in (root / "capture-journal.jsonl").read_text().splitlines())


def test_resume_preserves_separate_connect_and_rmc_recordings(tmp_path):
    root = tmp_path / "recordings"
    root.mkdir()
    connect = {"method": "GET", "host": "static3.cdn.ubi.com", "path": "/connect", "status": 200,
               "content_type": "application/json", "body_b64": base64.b64encode(b"{}").decode()}
    rmc = {"GameStorageProtocol::GetGameParamaters_V1": [
        {"params_sha1": "00", "params_len": 0, "body": "01"}]}
    (root / "connect-fixtures.json").write_text(json.dumps([connect]))
    (root / "fixtures-rmc.json").write_text(json.dumps(rmc))

    store = RecordingStore(root)
    store.record_http("GET", HOST, "/game", 200, "application/json", b"{}", target="game")
    store.close()

    assert json.loads((root / "connect-fixtures.json").read_text()) == [connect]
    assert json.loads((root / "fixtures-rmc.json").read_text()) == rmc


def test_classified_game_fixture_does_not_seed_connect_privacy_markers(tmp_path):
    root = tmp_path / "recordings"
    store = RecordingStore(root)
    config = {"configuration": {}, "username": "game-wide-config-label"}
    store.record_http("GET", HOST, f"/v2/applications/{APP_ID}/configuration", 200,
                      "application/json", _body(config), target="game")
    store.close()

    report = build(root, tmp_path / "gamedata")
    assert not report.findings


def test_failed_offer_response_is_marker_input_not_pack_data(tmp_path):
    root = tmp_path / "recordings"
    store = RecordingStore(root)
    store.record_http("GET", HOST, f"/v1/spaces/{SPACE_ID}/offers?offset=0&limit=100", 401,
                      "text/html", b"not json", target="game")
    store.record_issue("body-too-large", "GET", HOST, "/private?ticket=not-persisted", "40 bytes exceeds 10")
    report = store.close()

    built = build(root, tmp_path / "gamedata")
    assert not built.findings and built.kept["offers.json"] == 0
    assert report["skipped_responses"][0]["path"] == "/private"
    assert "ticket" not in json.dumps(report["skipped_responses"])
    assert not report["semantic_complete"]


def test_pack_builder_uses_latest_resumed_ownership_reply():
    def reply(label):
        product = pb.encode([(1, 3280), (17, label)])
        return pb.encode([(1, [(1, 1), (2, [(1, 1), (2, [(1, product)]), (5, 0), (6, 0)])])])

    demux = {"services": {"ownership_service": {"2": [
        base64.b64encode(reply("old")).decode(), base64.b64encode(reply("new")).decode()]}}}
    products = _products(demux)
    assert len(products) == 1 and pb.text(pb.decode(products[0]), 17) == "new"


def test_pack_builder_skips_malformed_latest_ownership_reply():
    product = pb.encode([(1, 3280), (17, "valid")])
    valid = pb.encode([(1, [(1, 1), (2, [(1, 1), (2, [(1, product)]), (5, 0), (6, 0)])])])
    malformed_product = pb.encode([(1, 3280), (16, b"not-protobuf")])
    malformed = pb.encode([
        (1, [(1, 1), (2, [(1, 1), (2, [(1, malformed_product)]), (5, 0), (6, 0)])])
    ])
    demux = {"services": {"ownership_service": {"2": [
        base64.b64encode(valid).decode(), base64.b64encode(malformed).decode()]}}}

    products = _products(demux)
    assert len(products) == 1 and pb.text(pb.decode(products[0]), 17) == "valid"


def test_malformed_existing_recording_is_never_silently_overwritten(tmp_path):
    root = tmp_path / "recordings"
    root.mkdir()
    bad = root / "connect-fixtures.json"
    bad.write_text("not-json")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        RecordingStore(root)
    assert bad.read_text() == "not-json"
