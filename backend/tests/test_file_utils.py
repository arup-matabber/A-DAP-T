"""
Unit tests for app.utils.file_utils.

Requirements covered:
  13.1 — Only ALLOWED_EXTENSIONS files are returned by get_scannable_files
  13.2 — Disallowed extension files are excluded
  13.3 — read_file_text UTF-8 / latin-1 fallback behaviour
  13.4 — read_file_text never raises; returns "" on any failure
"""

import os
import stat
import sys
from unittest.mock import patch, mock_open

import pytest

from app.utils.file_utils import ALLOWED_EXTENSIONS, get_scannable_files, read_file_text


# ---------------------------------------------------------------------------
# get_scannable_files — extension filtering (Requirements 13.1, 13.2)
# ---------------------------------------------------------------------------

ALLOWED_SAMPLE_EXTENSIONS = [".py", ".js", ".jsx", ".ts", ".tsx", ".json",
                              ".env", ".md", ".txt", ".yml", ".yaml", ".toml"]

DISALLOWED_EXTENSIONS = [".exe", ".pdf", ".zip", ".png", ".jpg", ".bin",
                         ".dll", ".mp4", ".csv", ".docx"]


class TestGetScannableFilesAllowedExtensions:
    """Req 13.1 — allowed extensions are returned."""

    @pytest.mark.parametrize("ext", ALLOWED_SAMPLE_EXTENSIONS)
    def test_returns_file_with_allowed_extension(self, tmp_path, ext):
        target = tmp_path / f"sample{ext}"
        target.write_text("content", encoding="utf-8")

        result = get_scannable_files(str(tmp_path))

        assert str(target.resolve()) in result

    def test_returns_all_allowed_files_in_directory(self, tmp_path):
        """Multiple allowed-extension files are all included."""
        files = []
        for ext in [".py", ".ts", ".json"]:
            f = tmp_path / f"file{ext}"
            f.write_text("x", encoding="utf-8")
            files.append(str(f.resolve()))

        result = get_scannable_files(str(tmp_path))

        for path in files:
            assert path in result


class TestGetScannableFilesDisallowedExtensions:
    """Req 13.2 — disallowed extensions are excluded."""

    @pytest.mark.parametrize("ext", DISALLOWED_EXTENSIONS)
    def test_excludes_file_with_disallowed_extension(self, tmp_path, ext):
        target = tmp_path / f"sample{ext}"
        target.write_bytes(b"\x00\x01\x02")  # binary content

        result = get_scannable_files(str(tmp_path))

        assert str(target.resolve()) not in result

    def test_mixed_directory_only_returns_allowed(self, tmp_path):
        """Directory with both allowed and disallowed files returns only allowed."""
        allowed = tmp_path / "script.py"
        disallowed = tmp_path / "archive.zip"
        allowed.write_text("pass", encoding="utf-8")
        disallowed.write_bytes(b"PK\x03\x04")

        result = get_scannable_files(str(tmp_path))

        assert str(allowed.resolve()) in result
        assert str(disallowed.resolve()) not in result


class TestGetScannableFilesEdgeCases:
    """Edge cases for get_scannable_files."""

    def test_nonexistent_directory_returns_empty_list(self):
        """Req 13.1 — non-existent directory does not raise; returns []."""
        result = get_scannable_files("/path/that/does/not/exist/at/all")
        assert result == []

    def test_empty_directory_returns_empty_list(self, tmp_path):
        result = get_scannable_files(str(tmp_path))
        assert result == []

    def test_recursive_subdirectory_discovery(self, tmp_path):
        """Files nested in subdirectories are found recursively."""
        sub = tmp_path / "deep" / "nested"
        sub.mkdir(parents=True)
        target = sub / "module.py"
        target.write_text("# nested", encoding="utf-8")

        result = get_scannable_files(str(tmp_path))

        assert str(target.resolve()) in result

    def test_extension_case_insensitive(self, tmp_path):
        """Extensions are matched case-insensitively (e.g. .PY treated as .py)."""
        upper = tmp_path / "script.PY"
        upper.write_text("x = 1", encoding="utf-8")

        result = get_scannable_files(str(tmp_path))

        assert str(upper.resolve()) in result

    def test_returns_absolute_paths(self, tmp_path):
        """All returned paths are absolute."""
        f = tmp_path / "a.py"
        f.write_text("", encoding="utf-8")

        result = get_scannable_files(str(tmp_path))

        assert all(os.path.isabs(p) for p in result)


# ---------------------------------------------------------------------------
# read_file_text — encoding behaviour (Requirements 13.3, 13.4)
# ---------------------------------------------------------------------------

class TestReadFileTextUtf8:
    """Req 13.3 — UTF-8 files are read correctly."""

    def test_reads_plain_ascii(self, tmp_path):
        f = tmp_path / "ascii.txt"
        f.write_text("hello world", encoding="utf-8")
        assert read_file_text(str(f)) == "hello world"

    def test_reads_utf8_multibyte_characters(self, tmp_path):
        content = "こんにちは — café — naïve"
        f = tmp_path / "unicode.py"
        f.write_text(content, encoding="utf-8")
        assert read_file_text(str(f)) == content

    def test_reads_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("", encoding="utf-8")
        assert read_file_text(str(f)) == ""


class TestReadFileTextLatin1Fallback:
    """Req 13.3 — latin-1 fallback when UTF-8 decoding fails."""

    def test_falls_back_to_latin1_for_non_utf8_bytes(self, tmp_path):
        """
        Write raw latin-1 bytes that are invalid UTF-8 (0x80–0xFF range).
        read_file_text must return the latin-1 decoded string, not raise.
        """
        # 0xe9 = 'é' in latin-1, but invalid as a standalone UTF-8 byte
        raw_bytes = b"caf\xe9"
        f = tmp_path / "latin1.txt"
        f.write_bytes(raw_bytes)

        result = read_file_text(str(f))

        assert result == raw_bytes.decode("latin-1")  # "café"
        assert result != ""  # must not silently return empty string

    def test_latin1_content_round_trips(self, tmp_path):
        """A file with multiple latin-1 special chars is decoded faithfully."""
        # Only use characters in the latin-1 range (U+0000–U+00FF)
        content_latin1 = "résumé naïve façade\n"
        raw = content_latin1.encode("latin-1")
        f = tmp_path / "resume.txt"
        f.write_bytes(raw)

        result = read_file_text(str(f))

        assert result == content_latin1


class TestReadFileTextFailureModes:
    """Req 13.4 — read_file_text never raises; returns "" on any failure."""

    def test_nonexistent_file_returns_empty_string(self):
        result = read_file_text("/no/such/file/ever.py")
        assert result == ""

    def test_nonexistent_file_does_not_raise(self):
        try:
            result = read_file_text("/no/such/file/ever.py")
        except Exception as exc:
            pytest.fail(f"read_file_text raised unexpectedly: {exc}")

    def test_permission_error_returns_empty_string(self, tmp_path):
        """Mock a PermissionError to verify graceful handling."""
        f = tmp_path / "secret.py"
        f.write_text("sensitive", encoding="utf-8")

        with patch("builtins.open", side_effect=PermissionError("access denied")):
            result = read_file_text(str(f))

        assert result == ""

    def test_permission_error_does_not_raise(self, tmp_path):
        f = tmp_path / "secret.py"
        f.write_text("data", encoding="utf-8")

        with patch("builtins.open", side_effect=PermissionError("access denied")):
            try:
                read_file_text(str(f))
            except Exception as exc:
                pytest.fail(f"read_file_text raised unexpectedly: {exc}")

    def test_os_error_returns_empty_string(self, tmp_path):
        """Any OSError (e.g. I/O error) also returns "" gracefully."""
        f = tmp_path / "broken.py"
        f.write_text("data", encoding="utf-8")

        with patch("builtins.open", side_effect=OSError("I/O error")):
            result = read_file_text(str(f))

        assert result == ""
