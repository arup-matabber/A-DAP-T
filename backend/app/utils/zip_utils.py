"""
Zip_Utils — ZIP validation, safe extraction, and cleanup for the A-DAP-T scanner.

This module provides:
  - validate_zip_meta(zip_path): enforce size / file-count / nesting-depth limits
  - extract_zip(zip_path, target_dir): safely extract with full security rule set
  - cleanup_temp_dir(temp_dir): delete a temporary directory tree, swallowing errors

Security invariants enforced by extract_zip (in application order):
  1. Zip-slip prevention via os.path.realpath
  2. Blocked directory skipping (node_modules, .git, dist, …)
  3. Lock-file skipping
  4. Symlink skipping
  5. Per-file size limit (500 KB)
  6. Extension allow-list
  7. Aggregate uncompressed size limit (200 MB)

Requirements: 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8,
              14.1, 14.2, 14.3, 14.4, 18.2, 18.3
"""

import logging
import os
import shutil
import zipfile

from fastapi import HTTPException

from app.utils.file_utils import ALLOWED_EXTENSIONS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BLOCKED_DIRS: set[str] = {
    "node_modules", ".git", "dist", "build",
    ".next", "venv", ".venv", "__pycache__", "coverage",
}

LOCK_FILES: set[str] = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}

MAX_ZIP_SIZE_BYTES    = 20 * 1024 * 1024   # 20 MB
MAX_FILE_COUNT        = 300
MAX_DEPTH             = 6
MAX_SINGLE_FILE_BYTES = 500 * 1024          # 500 KB
MAX_AGGREGATE_BYTES   = 200 * 1024 * 1024  # 200 MB


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_zip_meta(zip_path: str) -> None:
    """
    Validate the ZIP archive at *zip_path* against structural limits.

    Raises:
        HTTPException(400): if the file is not a valid ZIP, exceeds 20 MB,
                            contains more than 300 entries, or has nesting
                            depth greater than 6.
    """
    # 1. Physical file size (Req 4.2)
    try:
        physical_size = os.path.getsize(zip_path)
    except OSError as exc:
        logger.warning("validate_zip_meta: cannot stat '%s': %s", zip_path, exc)
        raise HTTPException(400, "Uploaded file is not a valid ZIP archive") from exc

    if physical_size > MAX_ZIP_SIZE_BYTES:
        raise HTTPException(400, "ZIP file exceeds 20 MB limit")

    # 2. Open and inspect the central directory (Req 4.2, 4.3, 4.4)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            entries = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, "Uploaded file is not a valid ZIP archive") from exc

    # 3. File count (Req 4.3)
    if len(entries) > MAX_FILE_COUNT:
        raise HTTPException(400, "ZIP contains more than 300 files")

    # 4. Nesting depth — count path components (Req 4.4)
    max_depth = max(
        (len(entry.filename.rstrip("/").split("/")) for entry in entries),
        default=0,
    )
    if max_depth > MAX_DEPTH:
        raise HTTPException(400, "ZIP nesting depth exceeds 6 levels")


def extract_zip(zip_path: str, target_dir: str) -> None:
    """
    Safely extract the ZIP archive at *zip_path* into *target_dir*.

    All security rules are applied in order for every entry:
      1. Zip-slip prevention
      2. Blocked directory skipping
      3. Lock-file skipping
      4. Symlink skipping
      5. Per-file size limit
      6. Extension allow-list
      7. Aggregate size limit

    *target_dir* should be a freshly created temporary directory produced by
    ``tempfile.mkdtemp()`` — no hardcoded paths are used here.

    Raises:
        HTTPException(400): on any security violation or archive corruption.
    """
    try:
        zf_handle = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, "ZIP extraction failed: corrupted archive") from exc

    resolved_target = os.path.realpath(target_dir)
    aggregate_bytes = 0

    with zf_handle as zf:
        for entry in zf.infolist():
            # ------------------------------------------------------------------
            # 1. Zip-slip prevention (Req 5.1, 14.1)
            # ------------------------------------------------------------------
            resolved_entry = os.path.realpath(
                os.path.join(target_dir, entry.filename)
            )
            if not resolved_entry.startswith(resolved_target + os.sep):
                raise HTTPException(
                    400,
                    "Zip-slip attempt detected \u2014 archive rejected",
                )

            # ------------------------------------------------------------------
            # 2. Skip blocked directories (Req 5.2, 5.3)
            # ------------------------------------------------------------------
            path_parts = entry.filename.replace("\\", "/").split("/")
            if any(part in BLOCKED_DIRS for part in path_parts):
                logger.debug("extract_zip: skipping blocked path: %s", entry.filename)
                continue

            # ------------------------------------------------------------------
            # 3. Skip lock files (Req 5.4)
            # ------------------------------------------------------------------
            filename_only = path_parts[-1] if path_parts else ""
            if filename_only in LOCK_FILES:
                logger.debug("extract_zip: skipping lock file: %s", entry.filename)
                continue

            # ------------------------------------------------------------------
            # 4. Skip directory entries (they are created on demand below)
            # ------------------------------------------------------------------
            if entry.filename.endswith("/"):
                continue

            # ------------------------------------------------------------------
            # 5. Skip symlinks (Req 5.5, 14.2)
            # ------------------------------------------------------------------
            # Unix symlinks are encoded in the external_attr high byte as 0xA
            unix_type = (entry.external_attr >> 28) & 0xF
            if unix_type == 0xA:
                logger.debug("extract_zip: skipping symlink: %s", entry.filename)
                continue

            # ------------------------------------------------------------------
            # 6. Per-file size limit (Req 5.6, 14.3)
            # ------------------------------------------------------------------
            if entry.file_size > MAX_SINGLE_FILE_BYTES:
                logger.debug(
                    "extract_zip: skipping oversized file (%d bytes): %s",
                    entry.file_size,
                    entry.filename,
                )
                continue

            # ------------------------------------------------------------------
            # 7. Extension allow-list (Req 5.5, 13.1)
            # ------------------------------------------------------------------
            _, ext = os.path.splitext(filename_only)
            if ext.lower() not in ALLOWED_EXTENSIONS:
                logger.debug(
                    "extract_zip: skipping disallowed extension '%s': %s",
                    ext,
                    entry.filename,
                )
                continue

            # ------------------------------------------------------------------
            # 8. Aggregate size check (Req 5.7, 5.8, 14.4)
            # ------------------------------------------------------------------
            aggregate_bytes += entry.file_size
            if aggregate_bytes > MAX_AGGREGATE_BYTES:
                raise HTTPException(
                    400,
                    "ZIP aggregate uncompressed size exceeds 200 MB",
                )

            # ------------------------------------------------------------------
            # Write the file (Req 18.2, 18.3)
            # ------------------------------------------------------------------
            dest_path = os.path.join(target_dir, entry.filename)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            try:
                with zf.open(entry) as src, open(dest_path, "wb") as dst:
                    dst.write(src.read())
            except (KeyError, OSError) as exc:
                logger.warning(
                    "extract_zip: failed to write '%s': %s", entry.filename, exc
                )
                raise HTTPException(
                    400, "ZIP extraction failed: corrupted archive"
                ) from exc


def cleanup_temp_dir(temp_dir: str) -> None:
    """
    Delete *temp_dir* and all its contents.

    Catches ``OSError`` and logs a warning instead of re-raising, so callers
    are never interrupted by cleanup failures.

    Args:
        temp_dir: Path to the temporary directory to remove.
    """
    try:
        shutil.rmtree(temp_dir)
        logger.debug("cleanup_temp_dir: removed '%s'", temp_dir)
    except OSError as exc:
        logger.warning(
            "cleanup_temp_dir: could not remove '%s': %s", temp_dir, exc
        )
