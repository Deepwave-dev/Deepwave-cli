from pathlib import Path
from typing import Optional
import tree_sitter_python as tspython
from loguru import logger
from tree_sitter import Language, Parser, Tree
from .base_parser import BaseParser


class TreeSitterParser(BaseParser):
    """Tree-sitter based parser for multiple languages"""

    def __init__(self, language_name: str, language_lib_path: Optional[str] = None):
        """Initialize Tree-sitter parser for a specific language."""
        self.language_name = language_name
        self.language_lib_path = language_lib_path
        self.language: Optional[Language] = None
        self.parser: Optional[Parser] = None
        self._initialize_parser()

    def _initialize_parser(self) -> None:
        """Initialize the Tree-sitter language and parser"""
        try:
            if self.language_lib_path:
                self.language = Language(self.language_lib_path, self.language_name)
            else:
                if self.language_name == "python":
                    try:
                        self.language = Language(tspython.language())
                    except ImportError:
                        logger.error("Please install tree-sitter-python: pip install tree-sitter-python")
                        raise ImportError("Could not import tree_sitter_python")
                else:
                    # For other languages, try the standard naming convention
                    module_name = f"tree_sitter_{self.language_name}"
                    try:
                        language_module = __import__(module_name)
                        if hasattr(language_module, "language"):
                            self.language = Language(language_module.language())
                        else:
                            raise ImportError(f"Module {module_name} does not have language() function")
                    except ImportError:
                        raise ImportError(
                            f"Could not import {module_name}. "
                            f"Please install tree-sitter-{self.language_name} or provide language_lib_path"
                        )

            # Parser constructor takes language directly in newer versions
            self.parser = Parser(self.language)
        except Exception as e:
            logger.error(f"Failed to initialize Tree-sitter parser for {self.language_name}: {e}")
            raise

    def parse(self, source_code: bytes) -> Optional[Tree]:
        """Parse source code bytes using Tree-sitter."""
        if not self.parser:
            self._initialize_parser()
        try:
            return self.parser.parse(source_code) if self.parser else None
        except Exception as e:
            logger.error(f"Parse failed: {e}")
            return None

    def parse_file(self, file_path: Path) -> Optional[Tree]:
        """Parse a file using Tree-sitter."""
        try:
            with open(file_path, "rb") as f:
                return self.parse(f.read())
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return None

    def get_language(self) -> str:
        """Return the language identifier"""
        return self.language_name

    def supports_file(self, file_path: Path) -> bool:
        """Check if this parser supports the given file based on extension."""
        extension_map = {
            "python": [".py"],
            "javascript": [".js", ".jsx"],
            "typescript": [".ts", ".tsx"],
        }

        extensions = extension_map.get(self.language_name, [])
        return file_path.suffix.lower() in extensions
