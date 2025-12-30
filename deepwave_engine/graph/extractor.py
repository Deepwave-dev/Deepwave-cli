"""
Repository scanning and file discovery.
"""

from pathlib import Path
from typing import List

from ..models import FileDetail
from ..ignore import is_excluded, detect_language, count_lines


def scan_repository(repo_path: Path) -> List[FileDetail]:
    """Scan entire repository file system to discover files and collect metadata."""
    file_details: List[FileDetail] = []
    try:
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file() or is_excluded(file_path):
                continue
            file_details.append(
                FileDetail(
                    path=str(file_path.relative_to(repo_path)),
                    language=detect_language(file_path),
                    size_bytes=file_path.stat().st_size,
                    line_count=count_lines(file_path),
                )
            )
    except Exception as e:
        raise Exception(f"Error analyzing repository structure: {e}")
    return file_details
