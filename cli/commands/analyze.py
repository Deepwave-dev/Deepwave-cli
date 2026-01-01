from pathlib import Path
from typing import Optional

import click

from cli.commands.upload import upload_bundle
from cli.services.analyze_service import (
    prepare_metadata,
    create_bundle,
)
from engine import analyze_repo
from engine.models import AnalysisResult


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
    repo_url: Optional[str],
    branch: Optional[str],
    commit_sha: Optional[str],
    output: Optional[Path],
    no_upload: bool,
    keep_files: bool,
) -> None:
    """Analyze a repository and create bundle."""
    try:
        click.echo(f"🔍 Analyzing repository: {repo_path}")

        # Prepare metadata
        metadata, git_root = prepare_metadata(repo_path, project_id, repo_url, branch, commit_sha)
        click.echo(f"  Git root: {git_root}")
        click.echo(f"  Repository: {metadata.repository_url}")
        click.echo(f"  Branch: {metadata.branch}")

        # Run analysis
        click.echo("  Running analysis...")
        result: AnalysisResult = analyze_repo(str(git_root), metadata)
        click.echo(f"  ✅ Analysis complete!")
        click.echo(f"     Nodes: {len(result.graph.nodes)}")
        click.echo(f"     Edges: {len(result.graph.edges)}")

        # Create bundle
        output_dir = output or Path.cwd()
        click.echo("  Creating bundle...")
        bundle_path = create_bundle(result, output_dir)
        click.echo(f"  ✅ Bundle created: {bundle_path.name}")

        # Upload (if requested)
        if not no_upload:
            click.echo("  Uploading bundle...")
            upload_bundle(bundle_path, project_id)
            click.echo("  ✅ Upload complete!")

        # Cleanup bundle file (unless --keep-files is used)
        if not keep_files and bundle_path.exists():
            bundle_path.unlink()
            click.echo("  🗑️  Bundle file cleaned up")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()
