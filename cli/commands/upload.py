import click
import httpx
from pathlib import Path
from typing import Optional

from cli.config import get_api_url, get_auth_token


def upload_bundle(bundle_path: Path, project_id: str, api_url: Optional[str] = None) -> None:
    """Upload bundle to server (internal function)."""
    api_url: str = api_url or get_api_url()
    token: Optional[str] = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    if not token:
        raise ValueError("Not authenticated. Run 'deepwave login' first.")

    with httpx.Client(timeout=30.0) as client:
        try:
            # Step 1: Create run
            create_response = client.post(f"{api_url}/api/v1/runs/", json={"project_id": project_id}, headers=headers)
            create_response.raise_for_status()
            run_data = create_response.json()
            run_id = run_data["id"]
        except Exception as e:
            raise Exception(f"Failed to create run: {e}") from e

        try:
            # Step 2: Upload bundle directly to backend
            with open(bundle_path, "rb") as f:
                files = {"file": (bundle_path.name, f, "application/zip")}
                upload_response = client.post(
                    f"{api_url}/api/v1/runs/{run_id}/upload", files=files, headers=headers, timeout=300.0
                )
                upload_response.raise_for_status()
        except Exception as e:
            raise Exception(f"Failed to upload bundle: {e}") from e

        try:
            # Step 3: Mark run as complete
            complete_response = client.post(f"{api_url}/api/v1/runs/{run_id}/complete", headers=headers, timeout=30.0)
            complete_response.raise_for_status()
        except Exception as e:
            raise Exception(f"Failed to mark run as complete: {e}") from e


@click.command()
@click.argument("bundle_path", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path))
@click.option("--project-id", required=True, help="Project ID/hash")
@click.option("--api-url", help="API base URL", default=None)
def upload(bundle_path: Path, project_id: str, api_url: str):
    """Upload bundle to server."""
    try:
        click.echo(f"📤 Uploading bundle: {bundle_path.name}")
        click.echo(f"   Project: {project_id}")

        upload_bundle(bundle_path, project_id, api_url)

        click.echo("✅ Upload complete!")
    except Exception as e:
        click.echo(f"Upload failed: {e}", err=True)
        raise click.Abort()
