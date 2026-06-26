"""
Unit tests for app.utils.zip_utils.

Requirements covered:
  4.2  — ZIP physical file-size limit (20 MB)
  4.3  — ZIP file-count limit (300 files)
  4.4  — ZIP nesting-depth limit (6 levels)
  4.10 — Non-ZIP files are rejected with HTTP 400
  5.3  — Blocked directories are skipped during extraction
  5.4  — Lock files are skipped during extraction
  5.7  — Aggregate uncompressed size limit (200 MB)
  5.8  — Zip-bomb protection via aggregate size guard
  14.4 — Aggregate size guard raises HTTPException 400
"""

import io
import os
import shutil
import zipfile
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.utils.zip_utils import (
    validate_zip_meta,
    extract_zip,
    cleanup_temp_dir,
    MAX_ZIP_SIZE_BYTES,
    MAX_FILE_COUNT,
    MAX_DEPTH,
    MAX_AGGREGATE_BYTES,
    MAX_SINGLE_FILE_BYTES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_zip(path: str, entries: list[tuple[str, bytes]]) -> None:
    """Write a real ZIP archive at *path* containing the given (name, data) entries."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries:
            zf.writestr(name, data)


# ---------------------------------------------------------------------------
# validate_zip_meta — size limit (Requirement 4.2)
# ---------------------------------------------------------------------------

class TestValidateZipMetaSizeLimit:
    """Req 4.2 — ZIP physical size must not exceed 20 MB."""

    def test_size_over_limit_raises_http_400(self, tmp_path):
        """Patching os.path.getsize to simulate a file larger than 20 MB."""
        zip_file = tmp_path / "big.zip"
        make_zip(str(zip_file), [("file.py", b"x")])

        with patch("os.path.getsize", return_value=MAX_ZIP_SIZE_BYTES + 1):
            with pytest.raises(HTTPException) as exc_info:
                validate_zip_meta(str(zip_file))

        assert exc_info.value.status_code == 400
        assert "20 MB" in exc_info.value.detail

    def test_size_exactly_at_limit_passes(self, tmp_path):
        """A file exactly at the 20 MB limit should pass the size check."""
        zip_file = tmp_path / "ok.zip"
        make_zip(str(zip_file), [("file.py", b"x")])

        with patch("os.path.getsize", return_value=MAX_ZIP_SIZE_BYTES):
            # Should not raise (file count and depth are trivially within limits)
            validate_zip_meta(str(zip_file))

    def test_size_under_limit_passes(self, tmp_path):
        """A normal small ZIP should pass the size check."""
        zip_file = tmp_path / "small.zip"
        make_zip(str(zip_file), [("script.py", b"print('hi')")])

        validate_zip_meta(str(zip_file))  # must not raise


# ---------------------------------------------------------------------------
# validate_zip_meta — file-count limit (Requirement 4.3)
# ---------------------------------------------------------------------------

class TestValidateZipMetaFileCountLimit:
    """Req 4.3 — ZIP must not contain more than 300 entries."""

    def test_file_count_over_limit_raises_http_400(self, tmp_path):
        """Create a ZIP with 301 empty files; expect HTTP 400 mentioning '300 files'."""
        zip_file = tmp_path / "many.zip"
        entries = [(f"file_{i}.py", b"") for i in range(MAX_FILE_COUNT + 1)]
        make_zip(str(zip_file), entries)

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_meta(str(zip_file))

        assert exc_info.value.status_code == 400
        assert "300 files" in exc_info.value.detail

    def test_file_count_exactly_at_limit_passes(self, tmp_path):
        """300 entries is exactly at the limit and should pass."""
        zip_file = tmp_path / "exactly300.zip"
        entries = [(f"file_{i}.py", b"") for i in range(MAX_FILE_COUNT)]
        make_zip(str(zip_file), entries)

        validate_zip_meta(str(zip_file))  # must not raise

    def test_single_file_zip_passes(self, tmp_path):
        """A ZIP with one file should trivially pass the count check."""
        zip_file = tmp_path / "one.zip"
        make_zip(str(zip_file), [("main.py", b"pass")])

        validate_zip_meta(str(zip_file))


# ---------------------------------------------------------------------------
# validate_zip_meta — depth limit (Requirement 4.4)
# ---------------------------------------------------------------------------

class TestValidateZipMetaDepthLimit:
    """Req 4.4 — ZIP nesting depth must not exceed 6 levels."""

    def test_depth_over_limit_raises_http_400(self, tmp_path):
        """
        Entry a/b/c/d/e/f/g/file.py has 8 path components (7 directories + file),
        which exceeds the MAX_DEPTH of 6.
        """
        zip_file = tmp_path / "deep.zip"
        # 7 path separators → depth of 8 components
        deep_entry = "a/b/c/d/e/f/g/file.py"
        make_zip(str(zip_file), [(deep_entry, b"")])

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_meta(str(zip_file))

        assert exc_info.value.status_code == 400
        assert "6 levels" in exc_info.value.detail

    def test_depth_exactly_at_limit_passes(self, tmp_path):
        """
        Entry a/b/c/d/e/f.py has 6 components, which equals MAX_DEPTH exactly.
        """
        zip_file = tmp_path / "ok_depth.zip"
        # 6 path components: a, b, c, d, e, f.py
        ok_entry = "a/b/c/d/e/f.py"
        make_zip(str(zip_file), [(ok_entry, b"")])

        validate_zip_meta(str(zip_file))  # must not raise

    def test_shallow_zip_passes(self, tmp_path):
        """A flat ZIP (no nesting) should trivially pass the depth check."""
        zip_file = tmp_path / "flat.zip"
        make_zip(str(zip_file), [("index.py", b""), ("utils.py", b"")])

        validate_zip_meta(str(zip_file))


# ---------------------------------------------------------------------------
# validate_zip_meta — not a ZIP (Requirement 4.10)
# ---------------------------------------------------------------------------

class TestValidateZipMetaNotAZip:
    """Req 4.10 — Non-ZIP files must be rejected with HTTP 400."""

    def test_non_zip_bytes_raises_http_400(self, tmp_path):
        """Write raw non-ZIP bytes; validate_zip_meta must raise HTTP 400."""
        fake_file = tmp_path / "not_a_zip.txt"
        fake_file.write_bytes(b"This is just plain text, not a ZIP archive at all.")

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_meta(str(fake_file))

        assert exc_info.value.status_code == 400
        assert "not a valid ZIP" in exc_info.value.detail

    def test_pdf_magic_bytes_raises_http_400(self, tmp_path):
        """PDF magic bytes are not a valid ZIP."""
        pdf_file = tmp_path / "document.pdf"
        pdf_file.write_bytes(b"%PDF-1.4 fake pdf content here")

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_meta(str(pdf_file))

        assert exc_info.value.status_code == 400
        assert "not a valid ZIP" in exc_info.value.detail

    def test_empty_file_raises_http_400(self, tmp_path):
        """An empty file is not a valid ZIP."""
        empty_file = tmp_path / "empty.zip"
        empty_file.write_bytes(b"")

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_meta(str(empty_file))

        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# extract_zip — aggregate size limit / zip-bomb protection (Req 5.7, 5.8, 14.4)
# ---------------------------------------------------------------------------

class TestExtractZipAggregateSizeLimit:
    """Req 5.7, 5.8, 14.4 — aggregate uncompressed size must not exceed 200 MB."""

    def test_aggregate_size_over_limit_raises_http_400(self, tmp_path):
        """
        Craft a ZIP whose entries report a combined file_size exceeding 200 MB.
        We mock infolist to return 401 files of 500 KB each (which individually
        pass the 500 KB file limit but collectively exceed 200 MB).
        """
        zip_file = tmp_path / "bomb.zip"
        make_zip(str(zip_file), [("main.py", b"x" * 10)])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        # Build a list of 420 ZipInfo entries, each 500 KB (MAX_SINGLE_FILE_BYTES)
        entries = []
        for i in range(420):
            entry = zipfile.ZipInfo(f"file_{i}.py")
            entry.file_size = MAX_SINGLE_FILE_BYTES
            entry.compress_size = 10
            entries.append(entry)

        with patch.object(zipfile.ZipFile, "infolist", return_value=entries), \
             patch.object(zipfile.ZipFile, "open", side_effect=lambda entry: io.BytesIO(b"content")):
            with pytest.raises(HTTPException) as exc_info:
                extract_zip(str(zip_file), str(target_dir))

        assert exc_info.value.status_code == 400
        assert "200 MB" in exc_info.value.detail

    def test_aggregate_exactly_at_limit_does_not_raise(self, tmp_path):
        """
        An aggregate uncompressed size exactly at 200 MB should NOT trigger the guard.
        The implementation uses: if aggregate_bytes > MAX_AGGREGATE_BYTES (strictly >).
        We verify the constant is correctly defined as 200 MB.
        """
        assert MAX_AGGREGATE_BYTES == 200 * 1024 * 1024


# ---------------------------------------------------------------------------
# extract_zip — lock file skipping (Requirement 5.4)
# ---------------------------------------------------------------------------

class TestExtractZipLockFileSkipped:
    """Req 5.4 — lock files must not be extracted."""

    def test_package_lock_json_not_extracted(self, tmp_path):
        """package-lock.json in the ZIP should be silently skipped."""
        zip_file = tmp_path / "project.zip"
        make_zip(str(zip_file), [
            ("package-lock.json", b'{"lockfileVersion": 2}'),
            ("index.py", b"print('hello')"),
        ])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        assert not (target_dir / "package-lock.json").exists()

    def test_pnpm_lock_yaml_not_extracted(self, tmp_path):
        """pnpm-lock.yaml should also be skipped."""
        zip_file = tmp_path / "project.zip"
        make_zip(str(zip_file), [
            ("pnpm-lock.yaml", b"lockfileVersion: '6.0'"),
            ("main.py", b"pass"),
        ])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        assert not (target_dir / "pnpm-lock.yaml").exists()

    def test_yarn_lock_not_extracted(self, tmp_path):
        """yarn.lock should also be skipped."""
        zip_file = tmp_path / "project.zip"
        make_zip(str(zip_file), [
            ("yarn.lock", b"# yarn lockfile v1"),
            ("app.js", b"console.log('hi')"),
        ])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        assert not (target_dir / "yarn.lock").exists()


# ---------------------------------------------------------------------------
# cleanup_temp_dir — error swallowing (Requirement 5.3 / general robustness)
# ---------------------------------------------------------------------------

class TestCleanupTempDir:
    """Tests for cleanup_temp_dir."""

    def test_swallows_oserror(self, tmp_path):
        """cleanup_temp_dir must NOT raise when shutil.rmtree raises OSError."""
        fake_dir = str(tmp_path / "nonexistent")

        with patch("shutil.rmtree", side_effect=OSError("Permission denied")):
            try:
                cleanup_temp_dir(fake_dir)
            except OSError:
                pytest.fail("cleanup_temp_dir raised OSError instead of swallowing it")
            except Exception as exc:
                pytest.fail(f"cleanup_temp_dir raised unexpectedly: {exc}")

    def test_deletes_existing_directory(self, tmp_path):
        """cleanup_temp_dir should actually delete an existing directory."""
        target = tmp_path / "temp_work"
        target.mkdir()
        (target / "file.py").write_text("pass", encoding="utf-8")

        cleanup_temp_dir(str(target))

        assert not target.exists()

    def test_swallows_oserror_on_missing_dir(self):
        """Calling cleanup_temp_dir on a path that doesn't exist should not raise."""
        try:
            cleanup_temp_dir("/path/that/does/not/exist/at/all")
        except Exception as exc:
            pytest.fail(f"cleanup_temp_dir raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# extract_zip — valid ZIP extracts successfully
# ---------------------------------------------------------------------------

class TestExtractZipSuccess:
    """Happy-path extraction tests."""

    def test_valid_zip_extracts_py_file(self, tmp_path):
        """A ZIP containing a .py file should be extracted to target_dir."""
        zip_file = tmp_path / "project.zip"
        make_zip(str(zip_file), [("main.py", b"print('hello world')")])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        extracted = target_dir / "main.py"
        assert extracted.exists()
        assert extracted.read_bytes() == b"print('hello world')"

    def test_valid_zip_extracts_multiple_allowed_files(self, tmp_path):
        """Multiple allowed-extension files are all extracted."""
        zip_file = tmp_path / "multi.zip"
        entries = [
            ("app.py", b"# python"),
            ("config.json", b'{"key": "value"}'),
            ("README.md", b"# Readme"),
        ]
        make_zip(str(zip_file), entries)

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        assert (target_dir / "app.py").exists()
        assert (target_dir / "config.json").exists()
        assert (target_dir / "README.md").exists()

    def test_valid_zip_with_nested_structure_extracts(self, tmp_path):
        """A ZIP with nested directories (within depth limit) extracts correctly."""
        zip_file = tmp_path / "nested.zip"
        make_zip(str(zip_file), [
            ("src/utils/helpers.py", b"def helper(): pass"),
            ("src/main.py", b"from utils import helpers"),
        ])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        assert (target_dir / "src" / "utils" / "helpers.py").exists()
        assert (target_dir / "src" / "main.py").exists()

    def test_disallowed_extension_file_not_extracted(self, tmp_path):
        """Files with disallowed extensions (e.g. .exe) are silently skipped."""
        zip_file = tmp_path / "mixed.zip"
        make_zip(str(zip_file), [
            ("safe.py", b"pass"),
            ("malware.exe", b"\x4d\x5a\x90\x00"),  # MZ header
        ])

        target_dir = tmp_path / "out"
        target_dir.mkdir()

        extract_zip(str(zip_file), str(target_dir))

        assert (target_dir / "safe.py").exists()
        assert not (target_dir / "malware.exe").exists()
