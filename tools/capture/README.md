# Capture a Powder game-data pack on Windows

This tool records the Ubisoft replies requested by your own copy of Steep and writes the private
`recordings/` input expected by Powder's existing game-data builder. It does not download game files,
guess account entitlements, or include Ubisoft data in this repository.

Use it only with a legitimately installed final-update (TU7) copy of Steep and your own Ubisoft account.
The resulting data may still be subject to Ubisoft's terms and copyright; this tool does not grant a right
to redistribute it.

## What the tool does

`capture.ps1` runs mitmproxy 12.3.1 in **local capture** mode. On Windows, local capture redirects the
selected processes at the networking layer, so it works even though Steep and Ubisoft Connect ignore
ordinary WinINet, `HTTP_PROXY`, or explicit-proxy settings. Earlier explicit-proxy/Wine experiments are
not a substitute for this workflow. Interception is restricted to Powder's seven pack-relevant HTTP hosts;
unrelated traffic from those processes passes through untouched. For the captured hosts, the runner
disables HTTP/3/QUIC: Chromium-based Ubisoft Connect does not trust a user-installed capture CA for QUIC,
so mitmproxy drops those handshakes and Connect falls back to capturable HTTP/2 or HTTP/1 over TCP.

The runner:

1. Refuses to start while Steep/Ubisoft Connect are open or Powder's hosts-file redirect is present.
2. Starts mitmproxy for only Steep and Ubisoft Connect process names and intercepts only the seven HTTP
   hosts used as pack sources. Windows may request elevation for mitmproxy's packet redirector.
3. Creates an isolated mitmproxy CA under the selected recordings directory, installs that exact CA in
   the current user's trusted roots, and starts Powder's existing Steep TLS helper. The helper is needed
   because Steep TU7 uses pinned, statically linked OpenSSL.
4. Records decoded HTTP replies without request headers. For progress import only, it also pairs the JSON
   body of Steep inventory-update POSTs with their replies; it does not retain other request bodies.
   Connect's proprietary demux TLS host is passed through untouched so that Connect remains online.
5. On exit, stops only the two child processes it started, removes the exact capture CA by thumbprint,
   and deletes the isolated CA private key. It leaves the recordings in place.

No system proxy or hosts-file entry is added by this tool.

The temporary mitmproxy CA is a general-purpose current-user root, not Powder's name-constrained server
CA. While it is installed, its private key can technically issue certificates for any hostname. The runner
keeps that key in its isolated directory, targets only the named game/Connect processes, and removes both
certificate and key on exit. Do not copy the key, run unrelated software through the recorder, or leave an
interrupted capture uncleaned. Put recordings in a directory accessible only to your Windows account.

## Prerequisites

- Windows 10 or 11.
- A legitimate Steam or Ubisoft Connect installation of Steep TU7.
- [`uv`](https://docs.astral.sh/uv/) (`uvx` is installed with it).
- `zig`, needed once to compile Powder's existing TU7 TLS helper.
- An internet connection. The first run downloads the pinned `mitmproxy==12.3.1` tool environment.

From a Powder checkout, build the native helper once:

```powershell
.\native\build.ps1
```

Close Steep, Ubisoft Connect, and any running Powder launcher/server. If Powder was used on this PC,
restore its DNS/certificate setup first:

```powershell
uv run powder --restore
```

## Record a session

Run this from the repository root. Choose a different directory if you do not want to use the already
gitignored `recordings/` folder:

```powershell
powershell -ExecutionPolicy Bypass -File tools\capture\capture.ps1 -Recordings .\recordings
```

Read the security explanations before accepting either Windows prompt. Do not start Ubisoft Connect until
the script prints **Recorder ready**. The TLS watcher waits up to 15 minutes for the game to start. Then:

1. Start Ubisoft Connect normally and sign in to your real account.
2. Launch Steep through Steam or Ubisoft Connect. The watcher supports only the two TU7 executable hashes
   listed in `powder/launcher/game.py`; it refuses unknown builds instead of injecting into them. **Stop at
   the title screen and do not press a key until the capture console says `TLS capture helper attached`.**
3. After that confirmation, continue to the online main menu and wait for the world/map to finish loading.
4. Open the in-game Store. Visit every sport, equipment, clothing, DLC, and reward category, and scroll
   each list to the end. Offer data is paged: seeing the first screen is not enough.
5. Open Ubisoft Club/Connect actions and rewards from the game where available.
6. Open the Ubisoft Connect overlay with Shift+F2, select Steep, open Achievements, and wait for names and
   icons to load. Also open the Steep game/details and owned-DLC views.
7. Return to the game for a minute so delayed configuration requests complete, then close Steep and
   Ubisoft Connect.
8. Press Ctrl+C in the capture console. Wait for confirmation that the temporary CA and private key were
   removed.

The recorder is resumable: running it again with the same recordings directory merges exact new replies
and preserves distinct response bodies. Read `recordings/capture-report.json` after every pass. In
particular, resolve skipped-response warnings, counts below the historical 2,000+ offers, missing
application/store configuration, actions, achievement ZIPs, or offer query families with no terminal
(short or empty) page. `semantic_complete` is deliberately conservative. A green pack hash check alone
cannot tell whether you visited every store page.

## Build and verify the pack

The capture directory is input; the output pack is a separate folder:

```powershell
uv run powder-server gamedata build .\recordings .\gamedata
uv run powder-server gamedata verify .\gamedata
uv run powder-server gamedata zip .\steep-gamedata.zip --pack .\gamedata
```

The build uses a strict allow-list, removes per-player state from Club actions, derives identifying markers
from the unkept replies, and refuses to produce a pack if any marker appears in the output. Do not bypass a
privacy failure. `verify` checks the manifest hashes; use `capture-report.json` for semantic coverage.

## Privacy

Treat the entire recordings directory as account data. Response bodies can contain profile/user IDs,
display names, friends, session tickets, inventory, progression, and other players. The addon deliberately
does **not** persist request headers (including Authorization and Cookie headers), but that does not make
the response archive safe to share.

- Do not commit, upload, paste, or publish `recordings/`, its journal, or mitmproxy state.
- The archive includes selected inventory-update request bodies used by Powder's progress importer.
- Do not send raw captures when asking for help. Share only counts and warning text with identifying values
  removed.
- Only the successfully built, privacy-checked `gamedata/` pack is designed to exclude player identity.
- Keep redistribution rights separate from the technical privacy check.

## Recovery and cleanup

Ctrl+C and ordinary failures run cleanup automatically. A power loss or forced process kill can leave the
temporary CA installed. Rerun the exact command with `-Cleanup` and the same recordings path:

```powershell
powershell -ExecutionPolicy Bypass -File tools\capture\capture.ps1 -Recordings .\recordings -Cleanup
```

Cleanup reads `.powder-capture-state.json`, verifies recorded process start times before stopping anything,
replays the crash journal into the canonical JSON files, removes only the recorded CA thumbprint, and
deletes only the `.powder-capture-mitmproxy` subdirectory. It does not delete recordings. If a child cannot
be verified/stopped or certificate removal fails, the state and CA directory are retained so the operation
can be retried.

If the capture console reports `Client QUIC handshake failed` with `CERTIFICATE_VERIFY_FAILED`, verify that
the runner contains the `http3=false` option and update the capture-tool branch. Do not work around this by
disabling certificate validation: QUIC is not needed for the recording, and the TCP fallback is safer.

## Protocol limitations

- `fixtures.json` and `connect-fixtures.json` are the pack's important HTTP sources. The tool keeps all
  relevant Ubisoft response bodies locally so Powder's privacy checker can derive personal markers.
- Ubisoft Connect's `dmx.upc.ubisoft.com` connection is deliberately passed through, not recorded. Its
  official edge closes the replacement upstream TLS connection made by mitmproxy, which makes Connect and
  Steep report offline. Demux would only supply exact owned-product/add-on metadata; Powder's built-in
  Steep product entries are used instead. The corresponding ownership warning in `capture-report.json` is
  expected and does not block pack construction.
- The tool does not record NEX/PRUDP. That channel uses ephemeral P-256 ECDH and AES-CBC, so a packet capture
  cannot be converted into decrypted RMC fixtures. This does not block the current pack: Powder now
  generates both pack-allowed RMC methods (`GetGameParamaters` and `FetchSeasonInfo`) itself.
- Store completeness depends on requests made during the session. Follow the checklist and the pagination
  warnings; the pack builder cannot infer pages the client never requested.
