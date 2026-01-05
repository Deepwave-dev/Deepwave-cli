import click

from cli import __version__
from cli.commands.login import login
from cli.commands.analyze import analyze
from cli.commands.upload import upload


@click.group()
@click.version_option(version=__version__, prog_name="deepwave")
def cli():
    """Deepwave CLI - Analyze repositories locally and upload results."""
    pass


cli.add_command(login)
cli.add_command(analyze)
cli.add_command(upload)


if __name__ == "__main__":
    cli()
