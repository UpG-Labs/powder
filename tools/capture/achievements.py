"""Import Steep's game-wide achievement definitions from Ubisoft Connect's cache.

Modern Connect serves the achievement page from GraphQL and normally reuses a
previously downloaded definitions archive.  Opening the page therefore does not
reliably produce the legacy CDN request that Powder needs for its pack.  This
module reads only Connect's achievement-cache directory, accepts only Steep's
public product ids, and rebuilds a bounded archive from definition members.  It
never reads Connect's account, ownership, browser, or session caches.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from tools.capture.recorder import RecordingStore


STEEP_PRODUCT_IDS = (3279, 3280)
CACHE_NAME = re.compile(
    rf"^(?:{'|'.join(str(product_id) for product_id in STEEP_PRODUCT_IDS)})_[0-9a-f]{{32}}(?:\.zip)?$",
    re.IGNORECASE,
)
LOCALE_NAME = re.compile(r"^([a-z]{2,3}(?:-[a-z0-9]{2,4})?)_loc\.txt$", re.IGNORECASE)
ICON_NAME = re.compile(r"^([0-9]+)\.png$", re.IGNORECASE)

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 512
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_LOCALE_BYTES = 2 * 1024 * 1024
MAX_ICON_BYTES = 8 * 1024 * 1024
MAX_DATA_BYTES = 8 * 1024 * 1024
MAX_ACHIEVEMENTS = 10_000
MAX_CACHE_ENTRIES = 4096
MAX_ICON_DIMENSION = 4096
MAX_ICON_PIXELS = 16 * 1024 * 1024

CDN_HOST = "static3.cdn.ubi.com"
CDN_PREFIX = "/orbit/uplay_launcher_3_0/assets"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
FORBIDDEN_TEXT_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class AchievementBundleError(ValueError):
    """The candidate is not a bounded Steep achievement-definition bundle."""


@dataclass(frozen=True)
class SanitizedBundle:
    body: bytes
    locale_count: int
    icon_count: int
    achievement_count: int


@dataclass(frozen=True)
class ImportResult:
    found: bool
    added: bool = False
    examined: int = 0
    locale_count: int = 0
    icon_count: int = 0
    achievement_count: int = 0


def default_cache_roots(environment: Mapping[str, str] | None = None) -> list[Path]:
    """Return only Ubisoft Connect's known achievement-cache directories."""
    env = os.environ if environment is None else environment
    roots: list[Path] = []
    program_data = str(env.get("ProgramData", "")).strip()
    local_app_data = str(env.get("LOCALAPPDATA", "")).strip()
    if program_data:
        roots.append(Path(program_data) / "Ubisoft" / "Ubisoft Game Launcher" / "cache" / "achievements")
    if local_app_data:
        roots.append(Path(local_app_data) / "Ubisoft Game Launcher" / "cache" / "achievements")
    # Preserve order while avoiding duplicate roots on unusual installations.
    return list(dict.fromkeys(roots))


def _canonical_locale_name(raw: str) -> str:
    match = LOCALE_NAME.fullmatch(raw)
    if match is None:
        raise AchievementBundleError("invalid locale member name")
    parts = match.group(1).split("-")
    locale = parts[0].lower()
    if len(parts) == 2:
        locale += "-" + (parts[1].upper() if len(parts[1]) == 2 else parts[1].title())
    return f"{locale}_loc.txt"


def _sanitize_locale(raw: bytes) -> tuple[bytes, set[int]]:
    if len(raw) > MAX_LOCALE_BYTES:
        raise AchievementBundleError("locale member is too large")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AchievementBundleError("locale member is not UTF-8") from exc
    rows: dict[int, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or re.fullmatch(r"[0-9]+", parts[0]) is None:
            continue
        achievement_id = int(parts[0])
        title, description = parts[1], parts[2]
        if not 0 <= achievement_id <= 2**31 - 1:
            continue
        if not title or len(title) > 512 or len(description) > 8192:
            continue
        if FORBIDDEN_TEXT_CONTROL.search(title) or FORBIDDEN_TEXT_CONTROL.search(description):
            continue
        rows.setdefault(achievement_id, (title, description))
        if len(rows) > MAX_ACHIEVEMENTS:
            raise AchievementBundleError("too many achievement definitions")
    if not rows:
        raise AchievementBundleError("locale member has no achievement definitions")
    canonical = "".join(
        f"{achievement_id}\t{title}\t{description}\n"
        for achievement_id, (title, description) in sorted(rows.items())
    )
    return b"\xef\xbb\xbf" + canonical.encode("utf-8"), set(rows)


def _validate_png(raw: bytes) -> None:
    """Validate bounded PNG structure, CRCs, and declared dimensions without decoding pixels."""
    if len(raw) > MAX_ICON_BYTES or not raw.startswith(PNG_MAGIC):
        raise AchievementBundleError("achievement icon is not a bounded PNG")
    offset = len(PNG_MAGIC)
    chunks = 0
    saw_header = False
    while offset < len(raw):
        if offset + 12 > len(raw):
            raise AchievementBundleError("achievement icon has a truncated PNG chunk")
        length = int.from_bytes(raw[offset:offset + 4], "big")
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + length
        if length > MAX_ICON_BYTES or end > len(raw):
            raise AchievementBundleError("achievement icon has an invalid PNG chunk size")
        data = raw[offset + 8:offset + 8 + length]
        expected_crc = int.from_bytes(raw[offset + 8 + length:end], "big")
        if zlib.crc32(kind + data) & 0xFFFFFFFF != expected_crc:
            raise AchievementBundleError("achievement icon has an invalid PNG checksum")
        chunks += 1
        if chunks > 256:
            raise AchievementBundleError("achievement icon has too many PNG chunks")
        if not saw_header:
            if kind != b"IHDR" or length != 13:
                raise AchievementBundleError("achievement icon has no leading PNG header")
            width = int.from_bytes(data[0:4], "big")
            height = int.from_bytes(data[4:8], "big")
            if (width <= 0 or height <= 0 or width > MAX_ICON_DIMENSION or height > MAX_ICON_DIMENSION
                    or width * height > MAX_ICON_PIXELS):
                raise AchievementBundleError("achievement icon dimensions are outside the limit")
            if data[10] != 0 or data[11] != 0 or data[12] not in (0, 1):
                raise AchievementBundleError("achievement icon uses unsupported PNG parameters")
            saw_header = True
        if kind == b"IEND":
            if length != 0 or end != len(raw):
                raise AchievementBundleError("achievement icon has an invalid PNG terminator")
            return
        offset = end
    raise AchievementBundleError("achievement icon has no PNG terminator")


def sanitize_achievement_bundle(path: Path) -> SanitizedBundle:
    """Validate and rebuild one cache candidate without unrelated archive members."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AchievementBundleError("candidate cannot be read") from exc
    if size <= 0 or size > MAX_ARCHIVE_BYTES:
        raise AchievementBundleError("candidate archive size is outside the limit")

    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise AchievementBundleError("candidate is not a ZIP archive") from exc

    members: dict[str, tuple[str, bytes]] = {}
    locale_ids: set[int] = set()
    icon_ids: set[int] = set()
    locale_names: set[str] = set()
    try:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
            raise AchievementBundleError("archive entry count is outside the limit")
        if sum(max(0, info.file_size) for info in infos) > MAX_UNCOMPRESSED_BYTES:
            raise AchievementBundleError("archive expands beyond the limit")
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 1:
                raise AchievementBundleError("archive has an encrypted member")
            # Ubisoft's definition archives are flat. Never preserve paths or alternate streams.
            name = info.filename.replace("\\", "/")
            if "/" in name or not name or ":" in name:
                continue
            locale_match = LOCALE_NAME.fullmatch(name)
            icon_match = ICON_NAME.fullmatch(name)
            is_data = name.lower() == "achievements.dat"
            if locale_match is None and icon_match is None and not is_data:
                continue
            limit = MAX_LOCALE_BYTES if locale_match else MAX_ICON_BYTES if icon_match else MAX_DATA_BYTES
            if info.file_size < 0 or info.file_size > limit:
                raise AchievementBundleError("definition member is outside the size limit")
            try:
                raw = archive.read(info)
            except (OSError, RuntimeError, NotImplementedError, zlib.error, zipfile.BadZipFile) as exc:
                raise AchievementBundleError("definition member failed validation") from exc
            if len(raw) != info.file_size:
                raise AchievementBundleError("definition member size changed while reading")
            if locale_match is not None:
                canonical_name = _canonical_locale_name(name)
                raw, ids = _sanitize_locale(raw)
                locale_ids.update(ids)
                locale_names.add(canonical_name.casefold())
            elif icon_match is not None:
                _validate_png(raw)
                achievement_id = int(icon_match.group(1))
                if not 0 <= achievement_id <= 2**31 - 1:
                    raise AchievementBundleError("achievement icon id is outside the limit")
                canonical_name = f"{achievement_id}.png"
                icon_ids.add(achievement_id)
            else:
                canonical_name = "achievements.dat"
            key = canonical_name.casefold()
            previous = members.get(key)
            if previous is not None and previous[1] != raw:
                raise AchievementBundleError("archive has conflicting definition members")
            members[key] = (canonical_name, raw)
    finally:
        archive.close()

    shared = locale_ids & icon_ids
    if "en-us_loc.txt" not in locale_names or not icon_ids or not shared:
        raise AchievementBundleError("archive lacks matching locale definitions and icons")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as rebuilt:
        for _, (name, raw) in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            rebuilt.writestr(info, raw)
    body = output.getvalue()
    if len(body) > MAX_ARCHIVE_BYTES:
        raise AchievementBundleError("rebuilt archive exceeds the limit")
    return SanitizedBundle(body, len(locale_names), len(icon_ids), len(shared))


def _candidate_paths(cache_roots: Iterable[Path]) -> list[Path]:
    candidates: list[tuple[int, Path]] = []
    for root in cache_roots:
        try:
            for index, path in enumerate(root.iterdir()):
                if index >= MAX_CACHE_ENTRIES:
                    break
                try:
                    if path.is_symlink() or not path.is_file() or CACHE_NAME.fullmatch(path.name) is None:
                        continue
                    modified = path.stat().st_mtime_ns
                except OSError:
                    continue
                candidates.append((modified, path))
        except OSError:
            continue
    return [path for _, path in sorted(candidates, key=lambda item: item[0], reverse=True)]


def import_cached_achievements(recordings: Path, cache_roots: Iterable[Path] | None = None) -> ImportResult:
    """Add the newest validated Steep cache bundle to an existing recording set."""
    examined = 0
    selected: SanitizedBundle | None = None
    for path in _candidate_paths(default_cache_roots() if cache_roots is None else cache_roots):
        examined += 1
        try:
            selected = sanitize_achievement_bundle(path)
        except AchievementBundleError:
            continue
        break
    if selected is None:
        return ImportResult(False, examined=examined)

    # Ubisoft's achievement asset basename is the archive's MD5 content key. This is not
    # used for security; matching the launcher's convention lets Connect validate/cache it.
    digest = hashlib.md5(selected.body, usedforsecurity=False).hexdigest()
    path = f"{CDN_PREFIX}/{digest}.zip"
    store = RecordingStore(recordings)
    try:
        added = store.record_http(
            "GET", CDN_HOST, path, 200, "application/octet-stream", selected.body, target="connect"
        )
    finally:
        store.close()
    return ImportResult(
        True,
        added=added,
        examined=examined,
        locale_count=selected.locale_count,
        icon_count=selected.icon_count,
        achievement_count=selected.achievement_count,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import Steep achievement definitions from Ubisoft Connect's local cache"
    )
    parser.add_argument("recordings", type=Path)
    parser.add_argument(
        "--cache-root", action="append", type=Path, default=None,
        help="override the achievement-cache directory (repeatable; primarily for diagnostics)",
    )
    args = parser.parse_args(argv)
    result = import_cached_achievements(args.recordings.expanduser().resolve(), args.cache_root)
    if not result.found:
        print(
            "achievement cache import: no validated Steep bundle found "
            f"({result.examined} candidate(s) examined)"
        )
        return 0
    action = "added" if result.added else "already present"
    print(
        f"achievement cache import: {action}; {result.achievement_count} definition(s), "
        f"{result.icon_count} icon(s), {result.locale_count} locale file(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
