from pathlib import Path
from git import Repo


def detect_git_root(path: Path) -> Path:
    """Detect git repository root from given path."""
    current = path.resolve()
    while current != current.parent:
        if (current / ".git").exists():
            return current
        current = current.parent
    return path


def get_git_info(repo_path: Path) -> tuple[str, str, str]:
    """Get git repository URL, branch, and commit SHA."""
    try:
        repo = Repo(repo_path)
        commit_sha = repo.head.object.hexsha
        branch = repo.active_branch.name
        remote = repo.remotes.origin
        repo_url = remote.url

        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        return repo_url, branch, commit_sha
    except Exception as e:
        raise Exception(f"Failed to get git info: {e}") from e
