from pathlib import Path
from typing import Any, Dict, List

from ..models import FileDetail


def build_file_tree(files: List[FileDetail]) -> Dict[str, Any]:
    """Build a minimal file tree structure optimized for LLM consumption.

    Creates the most compact structure possible - just folder hierarchy and file names:
    {
        "src": {
            "main.py": {},
            "utils": {
                "helpers.py": {}
            }
        },
        "tests": {
            "test_main.py": {}
        }
    }
    """
    tree: Dict[str, Any] = {}

    for file_detail in files:
        path_parts = Path(file_detail.path).parts

        if any(part.startswith(".") for part in path_parts):
            continue

        current = tree
        for part in path_parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        filename = path_parts[-1]
        current[filename] = {}

    return tree
