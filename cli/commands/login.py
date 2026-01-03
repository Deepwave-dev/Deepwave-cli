from typing import Optional

import click

from cli.auth import device_code_flow, login_with_token
from cli.config import get_api_url, set_auth_token


@click.command()
@click.option("--token", help="Authentication token")
@click.option("--api-url", help="API base URL", default=None)
def login(token: Optional[str], api_url: Optional[str]) -> None:
    """Authenticate with the API using a token or device code"""
    api_url = api_url or get_api_url()

    try:
        if token:
            if not login_with_token(token, api_url):
                click.echo("❌ Login failed: Invalid token", err=True)
                raise click.Abort()
            set_auth_token(token)
            click.echo("✅ Login successful!")
        else:
            click.echo("Starting device code OAuth flow...")
            token = device_code_flow(api_url)
            set_auth_token(token)
            click.echo("✅ Login successful!")
    except Exception as e:
        error_msg = str(e) if str(e) else "Unknown error"
        click.echo(f"❌ Authentication failed: {error_msg}", err=True)
        raise click.Abort()
