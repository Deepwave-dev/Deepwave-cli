from datetime import datetime
from pathlib import Path
from typing import List, Optional

from cli import __version__
from cli.utils import detect_git_root, get_git_info
from engine.bundle import write_bundle
from engine.models import AnalysisResult, ProjectMetadata


def prepare_metadata(
    repo_path: Path,
    project_id: str,
    repo_url: Optional[str] = None,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
) -> tuple[ProjectMetadata, Path]:
    """Prepare project metadata from git info and user inputs."""
    if not project_id or not project_id.strip():
        raise ValueError("project_id cannot be empty")

    git_root: Path = detect_git_root(repo_path)
    detected_url, detected_branch, detected_commit = get_git_info(git_root)

    repo_url = repo_url or detected_url
    branch = branch or detected_branch
    commit_sha = commit_sha or detected_commit

    if repo_url == "unknown":
        raise ValueError("Could not detect repository URL from git. Please provide --repo-url")

    repo_name: str = repo_url.split("/")[-1].replace(".git", "")

    metadata = ProjectMetadata(
        project_hash=project_id,
        repository_url=repo_url,
        repository_name=repo_name,
        branch=branch,
        commit_sha=commit_sha,
        parsed_at=datetime.now().isoformat(),
    )

    return metadata, git_root


def create_bundle(result: AnalysisResult, output_dir: Path, tool_version: Optional[str] = None) -> Path:
    """Create bundle from analysis result and write it to the output directory."""
    tool_version = tool_version or __version__
    try:
        bundle_path: Path = write_bundle(result, output_dir, tool_version=tool_version)

        intermediate_files: List[Path] = [
            output_dir / "manifest.json",
            output_dir / "graph.json",
            output_dir / "chunks.jsonl",
            output_dir / "stats.json",
        ]

        for json_file in intermediate_files:
            if json_file.exists():
                json_file.unlink()
        return bundle_path
    except Exception as e:
        raise RuntimeError(f"Bundle creation failed: {e}") from e
