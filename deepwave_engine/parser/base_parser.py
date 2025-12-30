from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Any


class BaseParser(ABC):
    """Abstract base class for language parsers"""

    @abstractmethod
    def parse_file(self, file_path: Path) -> Optional[Any]:
        """
        Parse a file and return a language-agnostic tree.

        Args:
            file_path: Path to the file to parse

        Returns:
            Parsed tree representation, or None if parsing fails
        """
        pass

    @abstractmethod
    def get_language(self) -> str:
        """
        Return the language identifier.

        Returns:
            Language identifier (e.g., "python", "javascript")
        """
        pass

    @abstractmethod
    def supports_file(self, file_path: Path) -> bool:
        """
        Check if this parser supports the given file.

        Args:
            file_path: Path to the file to check

        Returns:
            True if this parser can parse the file, False otherwise
        """
        pass
