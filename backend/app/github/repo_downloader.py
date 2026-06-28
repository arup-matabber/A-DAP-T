from __future__ import annotations

import os
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import HTTPException

from app.github.github_url_validator import GitHubRepoRef
from app.utils.zip_utils import MAX_ZIP_SIZE_BYTES


_GITHUB_ZIP_TIMEOUT_SECONDS = 20
_USER_AGENT = "A-DAP-T/2.0 repo-scanner"


def _candidate_branches(repo: GitHubRepoRef) -> list[str]:
    if repo.branch:
        return [repo.branch]
    return ["main", "master"]


def _zip_url(repo: GitHubRepoRef, branch: str) -> str:
    return f"https://github.com/{repo.owner}/{repo.repo}/archive/refs/heads/{branch}.zip"


def download_public_repo_zip(repo: GitHubRepoRef) -> str:
    """Download a public GitHub repo ZIP to a temp file and return the local path."""
    errors: list[str] = []

    for branch in _candidate_branches(repo):
        url = _zip_url(repo, branch)
        request = Request(url, headers={"User-Agent": _USER_AGENT})

        try:
            with urlopen(request, timeout=_GITHUB_ZIP_TIMEOUT_SECONDS) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_ZIP_SIZE_BYTES:
                    raise HTTPException(status_code=400, detail="GitHub repository ZIP exceeds 20 MB limit")

                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    total = 0
                    while True:
                        chunk = response.read(1024 * 256)
                        if not chunk:
                            break

                        total += len(chunk)
                        if total > MAX_ZIP_SIZE_BYTES:
                            tmp.close()
                            try:
                                os.unlink(tmp.name)
                            except OSError:
                                pass
                            raise HTTPException(status_code=400, detail="GitHub repository ZIP exceeds 20 MB limit")

                        tmp.write(chunk)

                    return tmp.name

        except HTTPException:
            raise
        except HTTPError as exc:
            errors.append(f"{branch}: HTTP {exc.code}")
        except URLError as exc:
            errors.append(f"{branch}: {exc.reason}")
        except TimeoutError:
            errors.append(f"{branch}: timed out")

    detail = "Could not download GitHub repository ZIP"
    if errors:
        detail += f" ({'; '.join(errors)})"
    raise HTTPException(status_code=400, detail=detail)
