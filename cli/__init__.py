"""Deepwave CLI - Command-line interface for repository analysis."""

from pathlib import Path

# Read version from VERSION file (single source of truth)
_version_file = Path(__file__).parent.parent / "VERSION"
if _version_file.exists():
    __version__ = _version_file.read_text().strip()
else:
    __version__ = "0.0.0"
