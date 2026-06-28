from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import HTTPException


_REPO_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class GitHubRepoRef:
    owner: str
    repo: str
    branch: str | None = None

    @property
    def display_name(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_github_repo_url(repo_url: str, branch: str | None = None) -> GitHubRepoRef:
    """Validate a public GitHub repository URL and return its owner/repo parts."""
    if not repo_url or not repo_url.strip():
        raise HTTPException(status_code=400, detail="GitHub repo URL is required")

    parsed = urlparse(repo_url.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise HTTPException(status_code=400, detail="Only https://github.com/<owner>/<repo> URLs are supported")

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="GitHub URL must include owner and repo")

    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not _REPO_PART_RE.match(owner) or not _REPO_PART_RE.match(repo):
        raise HTTPException(status_code=400, detail="GitHub owner/repo contains invalid characters")

    url_branch = None
    if len(parts) >= 4 and parts[2] == "tree":
        url_branch = "/".join(parts[3:])
    elif len(parts) > 2:
        raise HTTPException(
            status_code=400,
            detail="Use the repository root URL or a /tree/<branch> URL",
        )

    selected_branch = (branch or url_branch or "").strip() or None
    if selected_branch and (".." in selected_branch or selected_branch.startswith("/")):
        raise HTTPException(status_code=400, detail="Invalid GitHub branch name")

    return GitHubRepoRef(owner=owner, repo=repo, branch=selected_branch)
