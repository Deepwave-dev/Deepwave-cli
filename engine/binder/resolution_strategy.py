from abc import ABC, abstractmethod
from typing import List, Optional

from engine.models import BaseNode, NodeType
from engine.binder import SymbolIndex


class ResolutionStrategy(ABC):
    """Defines which node types a framework should resolve and how to find them."""

    @abstractmethod
    def get_resolution_types(self) -> List[NodeType]:
        """Return list of node types this framework resolves."""
        pass

    @abstractmethod
    def find_local_instances(self, symbol_index: SymbolIndex, file_rel: str, identifier: str) -> Optional[BaseNode]:
        """Find local instances in the same file."""
        pass

    @abstractmethod
    def find_by_module(self, symbol_index: SymbolIndex, module_path: str, identifier: str) -> Optional[BaseNode]:
        """Find component by module path."""
        pass

    @abstractmethod
    def find_by_file(self, symbol_index: SymbolIndex, file_rel: str, identifier: str) -> Optional[BaseNode]:
        """Find component by file path."""
        pass

    def find_attribute_by_module(
        self, symbol_index: SymbolIndex, module_path: str, attribute_name: str
    ) -> Optional[BaseNode]:
        """Find component by module path for attribute access (default uses find_by_module)."""
        return self.find_by_module(symbol_index, module_path, attribute_name)

    def find_attribute_by_file(
        self, symbol_index: SymbolIndex, file_rel: str, attribute_name: str
    ) -> Optional[BaseNode]:
        """Find component by file path for attribute access (default uses find_by_file)."""
        return self.find_by_file(symbol_index, file_rel, attribute_name)
