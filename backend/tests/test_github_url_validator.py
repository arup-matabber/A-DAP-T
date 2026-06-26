import pytest
from fastapi import HTTPException

from app.github.github_url_validator import parse_github_repo_url


def test_accepts_basic_github_repo_url():
    repo = parse_github_repo_url("https://github.com/openai/openai-python")
    assert repo.owner == "openai"
    assert repo.repo == "openai-python"
    assert repo.branch is None


def test_accepts_tree_branch_url():
    repo = parse_github_repo_url("https://github.com/user/repo/tree/dev")
    assert repo.owner == "user"
    assert repo.repo == "repo"
    assert repo.branch == "dev"


def test_explicit_branch_overrides_url_branch():
    repo = parse_github_repo_url("https://github.com/user/repo/tree/dev", branch="main")
    assert repo.branch == "main"


def test_rejects_non_github_urls():
    with pytest.raises(HTTPException):
        parse_github_repo_url("https://example.com/user/repo")


def test_rejects_extra_paths_that_are_not_tree_branches():
    with pytest.raises(HTTPException):
        parse_github_repo_url("https://github.com/user/repo/issues/1")
