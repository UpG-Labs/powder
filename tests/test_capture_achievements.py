import base64
import hashlib
import io
import json
import os
import struct
import zlib
import zipfile
from pathlib import Path

import pytest

from tools.capture.achievements import (
    AchievementBundleError,
    MAX_LOCALE_BYTES,
    default_cache_roots,
    import_cached_achievements,
    sanitize_achievement_bundle,
)
from powder.server.gamedata import privacy


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


def _png(width=1, height=1, pixel=b"\x00\x00\x00\xff") -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    pixels = b"".join(b"\x00" + pixel * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(pixels))
        + _png_chunk(b"IEND", b"")
    )


PNG = _png()


def _bundle(path: Path, *, locale=True, icon=True, noise=True, locale_name="en-us_loc.txt",
            locale_text=None, icon_body=PNG) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if locale:
            archive.writestr(
                locale_name,
                locale_text or (
                    "\ufeff1\tFirst run\tComplete the tutorial\n"
                    "2\tSecond run\tComplete another event\textra ignored field\n"
                    "not-an-id\tPrivate-looking noise\tignored\n"
                ),
            )
        if icon:
            archive.writestr("1.PNG", icon_body)
            archive.writestr("2.png", icon_body)
        archive.writestr("achievements.dat", b"public-definition-table")
        if noise:
            archive.writestr("../account.txt", b"must not leave the cache importer")
            archive.writestr("unrelated.json", b'{"ticket":"must not leave"}')


def test_default_cache_roots_are_narrow_and_environment_derived():
    roots = default_cache_roots({"ProgramData": "C:/ProgramData", "LOCALAPPDATA": "C:/Users/me/AppData/Local"})
    assert [str(path).replace("\\", "/") for path in roots] == [
        "C:/ProgramData/Ubisoft/Ubisoft Game Launcher/cache/achievements",
        "C:/Users/me/AppData/Local/Ubisoft Game Launcher/cache/achievements",
    ]
    assert default_cache_roots({}) == []


def test_cached_bundle_is_validated_and_rebuilt_without_unrelated_members(tmp_path):
    source = tmp_path / "3279_0123456789abcdef0123456789abcdef"
    _bundle(source)

    result = sanitize_achievement_bundle(source)
    assert (result.locale_count, result.icon_count, result.achievement_count) == (1, 2, 2)
    assert sanitize_achievement_bundle(source).body == result.body
    assert b"must not leave" not in result.body
    with zipfile.ZipFile(io.BytesIO(result.body)) as archive:
        assert archive.namelist() == ["1.png", "2.png", "achievements.dat", "en-US_loc.txt"]
        assert archive.read("1.png").startswith(b"\x89PNG")
        locale = archive.read("en-US_loc.txt").decode("utf-8-sig")
        assert locale == (
            "1\tFirst run\tComplete the tutorial\n"
            "2\tSecond run\tComplete another event\n"
        )


@pytest.mark.parametrize("locale,icon", [(False, True), (True, False)])
def test_cached_bundle_requires_matching_definitions_and_icons(tmp_path, locale, icon):
    source = tmp_path / "3280_0123456789abcdef0123456789abcdef"
    _bundle(source, locale=locale, icon=icon)
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(source)


def test_cached_bundle_requires_english_locale(tmp_path):
    source = tmp_path / "3280_0123456789abcdef0123456789abcdef"
    _bundle(source, locale_name="fr-FR_loc.txt")
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(source)


def test_cached_bundle_preserves_a_numeric_locale_region(tmp_path):
    source = tmp_path / "3279_0123456789abcdef0123456789abcdef"
    _bundle(source)
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr("es-419_loc.txt", "1\tPrimera bajada\tCompleta el tutorial\n")
    result = sanitize_achievement_bundle(source)
    with zipfile.ZipFile(io.BytesIO(result.body)) as archive:
        assert "es-419_loc.txt" in archive.namelist()


def test_cached_bundle_rejects_control_text_and_invalid_png_dimensions(tmp_path):
    bad_text = tmp_path / "3279_0123456789abcdef0123456789abcdef"
    _bundle(bad_text, locale_text="1\tBad\x01title\tDescription\n")
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(bad_text)

    bad_icon = tmp_path / "3280_fedcba9876543210fedcba9876543210"
    _bundle(bad_icon, icon_body=_png(width=5000))
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(bad_icon)


def test_cached_bundle_rejects_conflicting_duplicate_members(tmp_path):
    source = tmp_path / "3279_0123456789abcdef0123456789abcdef"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("en-US_loc.txt", "1\tOne\tFirst\n")
        archive.writestr("1.png", _png())
        archive.writestr("1.PNG", _png(width=2))
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(source)


def test_cached_bundle_rejects_oversized_and_encrypted_definition_members(tmp_path):
    oversized = tmp_path / "3279_0123456789abcdef0123456789abcdef"
    with zipfile.ZipFile(oversized, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("en-US_loc.txt", b"1\tName\t" + b"x" * MAX_LOCALE_BYTES)
        archive.writestr("1.png", PNG)
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(oversized)

    encrypted = tmp_path / "3280_fedcba9876543210fedcba9876543210"
    _bundle(encrypted)
    raw = bytearray(encrypted.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while (index := raw.find(signature, start)) >= 0:
            flags = int.from_bytes(raw[index + flag_offset:index + flag_offset + 2], "little") | 1
            raw[index + flag_offset:index + flag_offset + 2] = flags.to_bytes(2, "little")
            start = index + 4
    encrypted.write_bytes(raw)
    with pytest.raises(AchievementBundleError):
        sanitize_achievement_bundle(encrypted)


def test_cache_import_records_a_canonical_resumable_connect_fixture(tmp_path):
    cache = tmp_path / "cache" / "achievements"
    _bundle(cache / "3280_0123456789abcdef0123456789abcdef")
    _bundle(cache / "9999_not-steep")
    (cache / "3279_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").write_bytes(b"not a zip")
    os.utime(cache / "3280_0123456789abcdef0123456789abcdef", ns=(1, 1))
    os.utime(cache / "3279_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ns=(2, 2))
    recordings = tmp_path / "recordings"

    first = import_cached_achievements(recordings, [cache])
    assert first.found and first.added and first.examined == 2
    assert first.achievement_count == 2

    fixtures = json.loads((recordings / "connect-fixtures.json").read_text())
    assert len(fixtures) == 1
    entry = fixtures[0]
    assert entry["method"] == "GET" and entry["host"] == "static3.cdn.ubi.com"
    assert entry["path"].startswith("/orbit/uplay_launcher_3_0/assets/")
    assert entry["path"].endswith(".zip")
    assert entry["status"] == 200 and entry["content_type"] == "application/octet-stream"
    body = base64.b64decode(entry["body_b64"])
    asset_name = entry["path"].rsplit("/", 1)[1]
    assert asset_name == hashlib.md5(body, usedforsecurity=False).hexdigest() + ".zip"
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert "en-US_loc.txt" in archive.namelist() and "1.png" in archive.namelist()
        assert "unrelated.json" not in archive.namelist()
    report = json.loads((recordings / "capture-report.json").read_text())
    assert report["achievement_zip"] is True

    second = import_cached_achievements(recordings, [cache])
    assert second.found and not second.added
    assert len(json.loads((recordings / "connect-fixtures.json").read_text())) == 1


def test_cache_import_uses_newest_valid_steep_candidate(tmp_path):
    cache = tmp_path / "cache"
    valid = cache / "3279_0123456789abcdef0123456789abcdef"
    invalid = cache / "3280_fedcba9876543210fedcba9876543210"
    _bundle(valid)
    _bundle(invalid, icon=False)
    os.utime(valid, ns=(1, 1))
    os.utime(invalid, ns=(2, 2))

    result = import_cached_achievements(tmp_path / "recordings", [cache])
    assert result.found and result.added and result.examined == 2


def test_cache_import_is_a_noop_without_a_valid_steep_candidate(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    _bundle(cache / "9999_0123456789abcdef0123456789abcdef")
    (cache / "3279_bad").write_bytes(b"not a zip")
    (cache / "3279_0123456789abcdef0123456789abcdef").write_bytes(b"not a zip")

    result = import_cached_achievements(tmp_path / "recordings", [cache])
    assert not result.found and not result.added and result.examined == 1
    assert not (tmp_path / "recordings").exists()


def test_privacy_check_scans_deflated_archive_members(tmp_path):
    archive_body = io.BytesIO()
    with zipfile.ZipFile(archive_body, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("en-US_loc.txt", "1\tName\tcontains-private-marker\n")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "http.json").write_text(json.dumps([{
        "body_b64": base64.b64encode(archive_body.getvalue()).decode("ascii")
    }]))

    findings = privacy.check(pack, {"private-marker"})
    assert any("ZIP member" in finding and "private-mark" in finding for finding in findings)


def test_privacy_check_rejects_a_malformed_embedded_archive(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "http.json").write_text(json.dumps([{
        "body_b64": base64.b64encode(b"PK not actually a ZIP").decode("ascii")
    }]))
    assert privacy.check(pack, set()) == ["http.json (decoded): embedded ZIP is malformed"]


def test_windows_runner_imports_cache_before_final_report():
    runner = Path(__file__).parents[1] / "tools" / "capture" / "capture.ps1"
    script = runner.read_text(encoding="utf-8")
    finally_start = script.index("finally {")
    importer = script.index("Invoke-AchievementCacheImporter $uv.Source", finally_start)
    finalizer = script.index("Invoke-RecorderFinalizer $uv.Source", importer)
    assert importer < finalizer
    assert "python -m tools.capture.achievements" in script
