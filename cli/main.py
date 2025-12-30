"""CLI entrypoint."""

import click
from pathlib import Path

from .commands.login import login
from .commands.analyze import analyze
from .commands.upload import upload


@click.group()
@click.version_option(version="1.0.0", prog_name="deepwave")
def cli():
    """Deepwave CLI - Analyze repositories locally and upload results."""
    pass


cli.add_command(login)
cli.add_command(analyze)
cli.add_command(upload)


if __name__ == "__main__":
    cli()
