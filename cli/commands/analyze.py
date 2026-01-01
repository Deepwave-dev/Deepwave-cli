"""Analyze command."""

import click
from pathlib import Path
from datetime import datetime
from git import Repo, InvalidGitRepositoryError

from engine import analyze_repo
from engine.models import ProjectMetadata
from engine.bundle import write_bundle
from cli.commands.upload import upload_bundle


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

        try:
            branch = repo.active_branch.name
        except (TypeError, ValueError):
            branch = "HEAD"

        try:
            remote = repo.remotes.origin
            repo_url = remote.url
            if repo_url.endswith(".git"):
                repo_url = repo_url[:-4]
        except (AttributeError, ValueError):
            repo_url = "unknown"

        return repo_url, branch, commit_sha
    except InvalidGitRepositoryError:
        return "unknown", "unknown", "unknown"


@click.command()
@click.argument("repo_path", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
@click.argument("project_id", required=True)
@click.option("--repo-url", help="Repository URL (auto-detected from git if not provided)")
@click.option("--branch", help="Branch name (auto-detected from git if not provided)")
@click.option("--commit-sha", help="Commit SHA (auto-detected from git if not provided)")
@click.option("--output", type=click.Path(path_type=Path), help="Output directory for bundle")
@click.option("--no-upload", is_flag=True, help="Skip automatic upload after bundle creation")
@click.option("--keep-files", is_flag=True, help="Keep bundle files after successful upload")
def analyze(
    repo_path: Path,
    project_id: str,
    repo_url: str,
    branch: str,
    commit_sha: str,
    output: Path,
    no_upload: bool,
    keep_files: bool,
):
    """Analyze a repository and create bundle."""
    click.echo(f"🔍 Analyzing repository: {repo_path}")

    git_root = detect_git_root(repo_path)
    click.echo(f"  Git root: {git_root}")

    detected_url, detected_branch, detected_commit = get_git_info(git_root)

    repo_url = repo_url or detected_url
    branch = branch or detected_branch
    commit_sha = commit_sha or detected_commit

    if repo_url == "unknown":
        click.echo("  ⚠️  Warning: Could not detect repository URL from git", err=True)
        click.echo("     Please provide --repo-url", err=True)
        raise click.Abort()

    repo_name = repo_url.split("/")[-1].replace(".git", "")

    metadata = ProjectMetadata(
        project_hash=project_id,
        repository_url=repo_url,
        repository_name=repo_name,
        branch=branch,
        commit_sha=commit_sha,
        parsed_at=datetime.now().isoformat(),
    )

    try:
        click.echo("  Running analysis...")
        result = analyze_repo(str(git_root), metadata)

        click.echo(f"  ✅ Analysis complete!")
        click.echo(f"     Nodes: {len(result['graph'].nodes)}")
        click.echo(f"     Edges: {len(result['graph'].edges)}")
        click.echo(f"     Files: {len(result['files'])}")

        output_dir = output or Path.cwd()
        click.echo(f"  Creating bundle...")
        bundle_path = write_bundle(result, output_dir, tool_version="1.0.0")

        # Clean up individual JSON files (they're in the ZIP)
        manifest_path = output_dir / "manifest.json"
        graph_path = output_dir / "graph.json"
        chunks_path = output_dir / "chunks.jsonl"
        stats_path = output_dir / "stats.json"

        for json_file in [manifest_path, graph_path, chunks_path, stats_path]:
            if json_file.exists():
                json_file.unlink()

        click.echo(f"  ✅ Bundle created: {bundle_path.name}")

        if not no_upload:
            click.echo(f"  Uploading bundle...")
            try:
                upload_bundle(bundle_path, project_id)
                click.echo(f"  ✅ Upload complete!")
            except Exception as e:
                click.echo(f"  ⚠️  Upload failed: {e}", err=True)

            # Delete bundle file after upload attempt (unless --keep-files is used)
            if not keep_files:
                if bundle_path.exists():
                    bundle_path.unlink()
                    click.echo(f"  🗑️  Bundle file cleaned up")

    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}", err=True)
        raise click.Abort()
