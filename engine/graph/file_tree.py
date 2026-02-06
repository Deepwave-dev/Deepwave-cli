"""File tree builder - creates optimized file tree structure for LLM consumption."""

from typing import Dict, Any, List
from pathlib import Path

from ..models import FileDetail


def build_file_tree(files: List[FileDetail]) -> Dict[str, Any]:
    """Build a nested file tree structure optimized for LLM consumption.
    
    Creates a tree structure like:
    {
        "type": "directory",
        "name": ".",
        "children": {
            "src": {
                "type": "directory",
                "name": "src",
                "children": {
                    "main.py": {
                        "type": "file",
                        "name": "main.py",
                        "language": "python",
                        "size_bytes": 1234,
                        "line_count": 45
                    }
                }
            }
        }
    }
    
    This structure is optimized for LLM consumption:
    - Flat nested structure (no arrays) for easy traversal
    - Minimal metadata (only essential info)
    - Directory structure clearly visible
    
    Args:
        files: List of FileDetail objects from scan_repository
        
    Returns:
        Nested dictionary representing the file tree
    """
    tree: Dict[str, Any] = {
        "type": "directory",
        "name": ".",
        "children": {}
    }
    
    for file_detail in files:
        path_parts = Path(file_detail.path).parts
        
        # Navigate/create directory structure
        current = tree["children"]
        for i, part in enumerate(path_parts[:-1]):  # All parts except the filename
            if part not in current:
                current[part] = {
                    "type": "directory",
                    "name": part,
                    "children": {}
                }
            current = current[part]["children"]
        
        # Add file node
        filename = path_parts[-1]
        current[filename] = {
            "type": "file",
            "name": filename,
            "language": file_detail.language,
            "size_bytes": file_detail.size_bytes,
            "line_count": file_detail.line_count,
        }
    
    return tree


def build_file_tree_compact(files: List[FileDetail]) -> Dict[str, Any]:
    """Build a more compact file tree structure.
    
    Alternative format that's even more LLM-friendly:
    {
        ".": {
            "src": {
                "main.py": {"lang": "python", "lines": 45},
                "utils": {
                    "helpers.py": {"lang": "python", "lines": 23}
                }
            }
        }
    }
    
    Args:
        files: List of FileDetail objects
        
    Returns:
        Compact nested dictionary
    """
    tree: Dict[str, Any] = {}
    
    for file_detail in files:
        path_parts = Path(file_detail.path).parts
        
        # Navigate/create structure
        current = tree
        for i, part in enumerate(path_parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # Add file with minimal metadata
        filename = path_parts[-1]
        current[filename] = {
            "lang": file_detail.language,
            "lines": file_detail.line_count,
        }
    
    return tree
