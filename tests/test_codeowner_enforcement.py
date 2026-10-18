"""Unit tests for AirTell code review codeowner authorization policy."""

from pathlib import Path

from airtell.scripts.code_review import get_codeowners, verify_codeowner_authorization


def test_get_codeowners_from_repo():
    repo_root = Path(__file__).resolve().parent.parent
    codeowners_file = repo_root / ".github" / "CODEOWNERS"
    assert codeowners_file.exists(), ".github/CODEOWNERS must exist in the repository"

    owners = get_codeowners(codeowners_file)
    assert "ncouture" in owners, "Expected 'ncouture' to be defined in .github/CODEOWNERS"


def test_verify_codeowner_authorization_success():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="ncouture",
        pr_author="ncouture",
    )
    assert authorized is True
    assert "Authorized" in reason


def test_verify_codeowner_authorization_unauthorized_author():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="ncouture",
        pr_author="unauthorized_contributor",
    )
    assert authorized is False
    assert "PR author '@unauthorized_contributor' is not a repository codeowner" in reason


def test_verify_codeowner_authorization_unauthorized_requester():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="unauthorized_requester",
        pr_author="ncouture",
    )
    assert authorized is False
    assert "Review requester '@unauthorized_requester' is not a repository codeowner" in reason


def test_verify_codeowner_authorization_case_insensitive():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="@NCOUTURE",
        pr_author="@NCouture",
    )
    assert authorized is True
