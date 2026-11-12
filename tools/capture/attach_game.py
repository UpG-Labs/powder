"""Safely attach Powder's TLS helper to a legitimate Steep TU7 process.

This small watcher is used by ``capture.ps1`` while mitmproxy local capture is
active.  It performs the same build check and unpacking check as Powder's normal
launcher before loading anything into the game process.  It does not launch the
game, change game files, or need administrator rights.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from powder.launcher import attach, game


def _alive(pid: int) -> bool:
    return pid in {p.pid for p in attach.game_processes()}


def _attach(pid: int) -> str:
    """Attach to one candidate. Return ``attached``, ``gone``, or ``failed``."""
    raw_path = attach.image_path(pid)
    if not raw_path:
        print(f"Steep pid {pid}: cannot read the executable path; helper not attached.", flush=True)
        return "failed"
    exe = Path(raw_path)
    try:
        build = game.supported_build(exe)
    except OSError as exc:
        print(f"Steep pid {pid}: cannot verify the executable ({exc}); helper not attached.", flush=True)
        return "failed"
    if build is None:
        print(
            f"Steep pid {pid}: this executable is not a supported TU7 build; "
            "helper not attached to avoid a crash.",
            flush=True,
        )
        return "failed"

    print(f"Steep pid {pid}: verified {build}; waiting for protected code to finish loading.", flush=True)
    state = attach.wait_unpacked(
        pid,
        game.TARGET_RVA,
        game.PATCH_SPOT_LEN,
        game.PATCH_SPOT_SHA256,
        timeout=60,
    )
    if state == attach.GONE:
        print(f"Steep pid {pid}: starter process exited; waiting for the game process.", flush=True)
        return "gone"
    if state != attach.READY:
        print(
            f"Steep pid {pid}: code did not reach the verified state within 60 seconds; "
            "helper not attached.",
            flush=True,
        )
        return "failed"

    try:
        attach.LOG.unlink(missing_ok=True)
    except OSError:
        pass
    for _ in range(20):
        if attach.load_dll(pid):
            break
        if not _alive(pid):
            return "gone"
        time.sleep(0.5)
    else:
        print(f"Steep pid {pid}: could not load the TLS helper.", flush=True)
        return "failed"

    for _ in range(100):
        if attach.log_has("attach"):
            break
        if not _alive(pid):
            return "gone"
        time.sleep(0.1)
    else:
        print(f"Steep pid {pid}: TLS helper did not confirm attachment.", flush=True)
        return "failed"

    armer = attach.start_armer(pid, log=lambda line: print(f"TLS helper: {line}", flush=True))
    print(
        f"Steep pid {pid}: TLS capture helper attached. Continue to the online menu and capture checklist.",
        flush=True,
    )
    try:
        while _alive(pid):
            time.sleep(0.5)
    except KeyboardInterrupt:
        if armer.poll() is None:
            armer.terminate()
        raise
    if armer.poll() is None:
        armer.terminate()
    print(f"Steep pid {pid}: game closed.", flush=True)
    return "attached"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", type=float, default=900, help="seconds to wait for Steep (default: 900)")
    args = parser.parse_args(argv)

    if sys.platform != "win32":
        print("The Steep TLS helper can only attach on Windows.", file=sys.stderr)
        return 2
    problem = attach.ready()
    if problem:
        print(problem, file=sys.stderr)
        return 2

    print("Waiting for Steep.exe. Start the game normally through Steam or Ubisoft Connect.", flush=True)
    deadline = time.monotonic() + max(1.0, args.wait)
    while time.monotonic() < deadline:
        pid = attach.wait_for_real_game(min(30.0, max(0.1, deadline - time.monotonic())))
        if pid is None:
            continue
        result = _attach(pid)
        if result == "attached":
            return 0
        if result == "failed":
            return 1
        # A short-lived starter exited. Give the actual game another two
        # minutes even if it appeared near the original deadline.
        deadline = max(deadline, time.monotonic() + 120)
    print("Steep did not start before the capture watcher timed out.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Steep TLS helper watcher stopped.", file=sys.stderr)
        raise SystemExit(130) from None
