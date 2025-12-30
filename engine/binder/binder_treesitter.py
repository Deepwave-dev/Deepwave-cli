"""Tree-sitter based Binder - maintains 100% compatibility with AST version"""

from pathlib import Path
from typing import Optional
from tree_sitter import Node as TSNode

from engine.models import BaseNode, ApplicationNode, RouterNode, ServiceClassNode
from .import_graph_treesitter import ImportGraphTreeSitter
from .symbol_index_treesitter import SymbolIndexTreeSitter


class BinderTreeSitter:
    """Bind Tree-sitter identifier/attribute nodes in a module/file to known nodes via imports and symbol index."""

    def __init__(
        self,
        project_path: Path,
        import_graph: ImportGraphTreeSitter,
        symbol_index: SymbolIndexTreeSitter,
    ) -> None:
        self.project_path = project_path
        self.import_graph = import_graph
        self.symbol_index = symbol_index

    def bind_name(self, module_name: str, file_path: Path, identifier_node: TSNode) -> Optional[BaseNode]:
        """
        Bind a Tree-sitter identifier node to a known node.
        Mirrors Binder.bind_name() exactly but works with Tree-sitter nodes.
        """
        if identifier_node.type != "identifier":
            return None

        identifier_text = identifier_node.text.decode("utf-8")
        file_rel = self._rel(file_path)

        # Local instances (apps/routers/services)
        n = (
            self.symbol_index.find_app(file_rel, identifier_text)
            or self.symbol_index.find_router(file_rel, identifier_text)
            or self.symbol_index.find_service_instance(file_rel, identifier_text)
        )
        if n:
            return n

        # Imported symbol
        resolved = self.import_graph.resolve_name(file_path, identifier_text)
        if not resolved:
            return None
        source_module, source_symbol = resolved
        lookup_symbol = source_symbol if source_symbol else identifier_text

        # Try module-path lookups: source module + all its submodules (handles re-exports)
        module_paths = {source_module}
        if source_symbol:
            module_paths.update([f"{source_module}.{source_symbol.lower()}", f"{source_module}.{source_symbol}"])
            prefix = f"{source_module}."
            module_paths.update(m for m in self.import_graph.module_to_file.keys() if m.startswith(prefix))

        for module_path in module_paths:
            app = self.symbol_index.find_app_by_module(module_path, lookup_symbol)
            if app:
                return app
            router = self.symbol_index.find_router_by_module(module_path, lookup_symbol)
            if router:
                return router

        # Fallback: file-based lookup
        source_file = self.import_graph.file_for_module(source_module)
        if source_file:
            src_rel = self._rel(source_file)
            sym = source_symbol or identifier_text
            result = (
                self.symbol_index.find_app(src_rel, sym)
                or self.symbol_index.find_router(src_rel, sym)
                or self.symbol_index.find_service_instance(src_rel, sym)
                or self.symbol_index.find_service_class(sym)
            )
            if result:
                return result

        return None

    def bind_attribute(self, module_name: str, file_path: Path, attribute_node: TSNode) -> Optional[BaseNode]:
        """
        Bind a Tree-sitter attribute node to a known node.
        Mirrors Binder.bind_attribute() exactly but works with Tree-sitter nodes.
        """
        if attribute_node.type != "attribute":
            return None

        # Extract object and attribute from Tree-sitter attribute node
        object_node = attribute_node.child_by_field_name("object")
        attribute_name_node = attribute_node.child_by_field_name("attribute")

        if not object_node or not attribute_name_node:
            return None

        attribute_name = attribute_name_node.text.decode("utf-8")

        # Handle nested attributes (e.g., router.get) - get the base identifier
        base_identifier = self._extract_base_identifier(object_node)
        if not base_identifier:
            return None

        base_text = base_identifier.text.decode("utf-8")

        # First try direct binding (uses submodule checking)
        bound = self.bind_name(module_name, file_path, base_identifier)
        if bound:
            return bound

        # Imported module/package - try module-path lookups with submodule checking
        resolved = self.import_graph.resolve_name(file_path, base_text)
        if not resolved:
            return None
        source_module, source_symbol = resolved

        # Try module-path lookups: source module + all its submodules
        module_paths = {source_module}
        if source_symbol:
            full_module = f"{source_module}.{source_symbol}"
            module_paths.add(full_module)
            module_paths.update([f"{full_module}.{attribute_name.lower()}", f"{full_module}.{attribute_name}"])
            prefix = f"{full_module}."
            module_paths.update(m for m in self.import_graph.module_to_file.keys() if m.startswith(prefix))
        else:
            module_paths.update([f"{source_module}.{attribute_name.lower()}", f"{source_module}.{attribute_name}"])
            prefix = f"{source_module}."
            module_paths.update(m for m in self.import_graph.module_to_file.keys() if m.startswith(prefix))

        for module_path in module_paths:
            node = self.symbol_index.find_router_by_module(
                module_path, attribute_name
            ) or self.symbol_index.find_app_by_module(module_path, attribute_name)
            if node:
                return node

        # Fallback: file-based lookup
        source_file = self.import_graph.file_for_module(source_module)
        if source_file:
            src_rel = self._rel(source_file)
            return (
                self.symbol_index.find_router(src_rel, attribute_name)
                or self.symbol_index.find_app(src_rel, attribute_name)
                or self.symbol_index.find_service_instance(src_rel, attribute_name)
            )
        return None

    def _extract_base_identifier(self, node: TSNode) -> Optional[TSNode]:
        """
        Extract the base identifier from a Tree-sitter node.
        Handles nested attributes by traversing to the base identifier.
        """
        if node.type == "identifier":
            return node
        elif node.type == "attribute":
            # Recursively get the object
            object_node = node.child_by_field_name("object")
            if object_node:
                return self._extract_base_identifier(object_node)
        return None

    def bind_expr(self, file_path: Path, expr_node: TSNode) -> Optional[BaseNode]:
        """Bind a Tree-sitter identifier or attribute expression to a known node deterministically."""
        if expr_node.type == "identifier":
            return self.bind_name("", file_path, expr_node)
        if expr_node.type == "attribute":
            return self.bind_attribute("", file_path, expr_node)
        return None

    def _rel(self, file_path: Path) -> str:
        return str(file_path.relative_to(self.project_path))
