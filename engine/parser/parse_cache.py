from pathlib import Path
from typing import Dict, Optional
from tree_sitter import Tree
from .tree_sitter_parser import TreeSitterParser


class ParseCache:
    """Cache module for file trees and file contents."""

    def __init__(self, project_path: Path, parser: Optional[TreeSitterParser] = None):
        self.project_path = project_path
        self.parser = parser or TreeSitterParser("python")
        self.trees: Dict[Path, Optional[Tree]] = {}
        self.file_contents: Dict[Path, str] = {}

    def get_tree(self, file_path: Path) -> Optional[Tree]:
        """Get parsed tree from cache"""
        return self.trees.get(file_path)

    def store_tree(self, file_path: Path, tree: Optional[Tree]) -> None:
        """Store a parsed tree in the cache"""
        self.trees[file_path] = tree

    def get_content(self, file_path: Path) -> Optional[str]:
        """Get file content from cache"""
        return self.file_contents.get(file_path)

    def store_content(self, file_path: Path, content: str) -> None:
        """Store file content in the cache"""
        self.file_contents[file_path] = content

    def clear(self):
        """Clear cache"""
        self.trees.clear()
        self.file_contents.clear()
