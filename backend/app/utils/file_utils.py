"""
File_Utils — shared file enumeration and reading utilities for the A-DAP-T scanner.

This module provides:
  - get_scannable_files(directory): recursively enumerate files with allowed extensions
  - read_file_text(path): safely read a file as UTF-8 with latin-1 fallback

Security invariant: this module never calls exec(), eval(), subprocess, or
os.system() on any content read from project files.
"""

import logging
import os

logger = logging.getLogger(__name__)

# Allowed file extensions the scanner is permitted to read (Requirement 13.1, 5.5)
ALLOWED_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".json", ".env", ".md", ".txt",
    ".yml", ".yaml", ".toml",
}


def get_scannable_files(directory: str) -> list[str]:
    """
    Recursively walk *directory* and return the absolute paths of every file
    whose extension (lowercased) is in ALLOWED_EXTENSIONS.

    Args:
        directory: Root directory to walk.

    Returns:
        A list of absolute file path strings.  Empty list if the directory
        does not exist or contains no matching files.
    """
    results: list[str] = []

    if not os.path.isdir(directory):
        logger.warning("get_scannable_files: directory does not exist: %s", directory)
        return results

    for root, _dirs, files in os.walk(directory):
        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext.lower() in ALLOWED_EXTENSIONS:
                absolute_path = os.path.abspath(os.path.join(root, filename))
                results.append(absolute_path)

    return results


def read_file_text(path: str) -> str:
    """
    Read and return the text content of the file at *path*.

    Attempt order:
      1. UTF-8
      2. latin-1 (fallback on UnicodeDecodeError)
      3. Return "" and log a warning if the file is still unreadable.

    This function never raises an unhandled exception regardless of the failure
    mode (missing file, permission error, binary-only content, etc.).

    Args:
        path: Absolute or relative path to the file.

    Returns:
        The file's text content, or an empty string on any read failure.
    """
    # Attempt 1: UTF-8
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        pass  # fall through to latin-1
    except Exception as exc:  # noqa: BLE001
        logger.warning("read_file_text: could not read '%s': %s", path, exc)
        return ""

    # Attempt 2: latin-1 fallback
    try:
        with open(path, encoding="latin-1") as fh:
            return fh.read()
    except Exception as exc:  # noqa: BLE001
        logger.warning("read_file_text: could not read '%s' even with latin-1 fallback: %s", path, exc)
        return ""
