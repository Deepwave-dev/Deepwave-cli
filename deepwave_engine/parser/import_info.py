"""Structured import information for ImportGraph"""

from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ImportInfo:
    """Structured information about an import statement"""

    import_type: str  # "import" or "import_from"
    module_name: Optional[str]  # Source module (None for relative imports without module)
    level: int  # Relative import level (0 = absolute, 1 = ".", 2 = "..", etc.)
    imports: List[Tuple[str, Optional[str]]]  # List of (name, alias) tuples

    def __post_init__(self):
        """Validate import info"""
        if self.import_type not in ["import", "import_from"]:
            raise ValueError(f"Invalid import_type: {self.import_type}")
        if self.level < 0:
            raise ValueError(f"Invalid level: {self.level}")
