"""Login command."""

import click
from ..config import get_api_url, set_auth_token
from ..auth import login_with_token, device_code_flow


@click.command()
@click.option("--token", help="Authentication token")
@click.option("--api-url", help="API base URL", default=None)
def login(token: str, api_url: str):
    """Authenticate with the API."""
    api_url = api_url or get_api_url()

    if token:
        if login_with_token(token, api_url):
            set_auth_token(token)
            click.echo("✅ Login successful!")
        else:
            click.echo("❌ Login failed: Invalid token", err=True)
            raise click.Abort()
    else:
        click.echo("Starting device code OAuth flow...")
        try:
            token = device_code_flow(api_url)
            set_auth_token(token)
            click.echo("✅ Login successful!")
        except NotImplementedError:
            click.echo("❌ Device code OAuth endpoint not available on backend.", err=True)
            click.echo("   Please use --token to provide your Firebase ID token manually.", err=True)
            raise click.Abort()
        except (ConnectionError, ValueError, TimeoutError) as e:
            click.echo(f"❌ Authentication failed: {e}", err=True)
            raise click.Abort()
