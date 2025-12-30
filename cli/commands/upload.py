"""Upload command."""

import click
import requests
from pathlib import Path
from typing import Optional

from cli.config import get_api_url, get_auth_token


def upload_bundle(bundle_path: Path, project_id: str, api_url: Optional[str] = None) -> None:
    """Upload bundle to server (internal function)."""
    api_url = api_url or get_api_url()
    token = get_auth_token()

    if not token:
        raise ValueError("Not authenticated. Run 'deepwave login' first.")

    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Create run
    try:
        create_response = requests.post(
            f"{api_url}/api/v1/runs", json={"project_id": project_id}, headers=headers, timeout=30
        )
        if create_response.status_code == 404:
            raise NotImplementedError("Runs endpoint not available on backend")
        create_response.raise_for_status()
        run_data = create_response.json()
        run_id = run_data["id"]
    except requests.exceptions.RequestException as e:
        if hasattr(e, "response") and e.response is not None and e.response.status_code == 404:
            raise NotImplementedError("Runs endpoint not available on backend")
        raise ConnectionError(f"Failed to create run: {e}")

    # Step 2: Upload bundle directly to backend
    try:
        with open(bundle_path, "rb") as f:
            files = {"file": (bundle_path.name, f, "application/zip")}
            upload_response = requests.post(
                f"{api_url}/api/v1/runs/{run_id}/upload", files=files, headers=headers, timeout=300
            )
            if upload_response.status_code == 404:
                raise NotImplementedError("Upload endpoint not available on backend")
            upload_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        if hasattr(e, "response") and e.response is not None and e.response.status_code == 404:
            raise NotImplementedError("Upload endpoint not available on backend")
        raise ConnectionError(f"Failed to upload bundle: {e}")

    # Step 4: Mark run as complete
    try:
        complete_response = requests.post(f"{api_url}/api/v1/runs/{run_id}/complete", headers=headers, timeout=30)
        if complete_response.status_code == 404:
            raise NotImplementedError("Complete endpoint not available on backend")
        complete_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to mark run as complete: {e}")


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
    except ValueError as e:
        click.echo(f"❌ {e}", err=True)
        raise click.Abort()
    except NotImplementedError as e:
        click.echo(f"❌ {e}", err=True)
        click.echo("   Backend endpoints not yet implemented.", err=True)
        raise click.Abort()
    except ConnectionError as e:
        click.echo(f"❌ Upload failed: {e}", err=True)
        raise click.Abort()
