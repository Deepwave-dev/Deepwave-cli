from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from tree_sitter import Node as TSNode

from engine.binder import ImportGraph, SymbolIndex
from engine.binder.resolution_strategy import ResolutionStrategy
from engine.models import BaseNode, ExpressionType, NodeType


class SymbolResolver:
    """Resolves identifiers and attributes to domain nodes using import information and symbol indices."""

    def __init__(
        self,
        project_path: Path,
        import_graph: ImportGraph,
        symbol_index: SymbolIndex,
        resolution_strategy: ResolutionStrategy,
    ):
        self.project_path = project_path
        self.import_graph = import_graph
        self.symbol_index = symbol_index
        self.strategy = resolution_strategy

        # Private attributes
        self.resolution_cache: Dict[Tuple[str, str, str], Optional[BaseNode]] = {}
        self.module_path_index: Dict[str, Set[str]] = {}

        # Build module path index
        self.build_module_path_index()

    def resolve_expression(self, file_path: Path, expr_node: TSNode) -> Optional[BaseNode]:
        """Resolve any expression (identifier, attribute, call, subscription, await) to a known domain node or None."""
        match expr_node.type:
            case ExpressionType.IDENTIFIER:
                return self.resolve_identifier(file_path, expr_node)
            case ExpressionType.ATTRIBUTE:
                return self.resolve_attribute_access(file_path, expr_node)
            case ExpressionType.CALL:
                return self.resolve_call(file_path, expr_node)
            case ExpressionType.SUBSCRIPTION:
                return self.resolve_subscription(file_path, expr_node)
            case ExpressionType.AWAIT:
                return self.resolve_await(file_path, expr_node)
            case _:
                return None

    def resolve_subscription(self, file_path: Path, subscription_node: TSNode) -> Optional[BaseNode]:
        """TODO: Implement subscription resolution."""
        return None

    def resolve_await(self, file_path: Path, await_node: TSNode) -> Optional[BaseNode]:
        """Resolve await expressions (e.g., await get_router()) by unwrapping to inner expression."""
        if await_node.type != ExpressionType.AWAIT:
            return None

        # Tree-sitter await nodes have no field names. Structure: [await keyword (unnamed), expression (named)]
        # The expression is always the first (and only) named child
        if await_node.named_child_count > 0:
            inner_expr = await_node.named_child(0)
            return self.resolve_expression(file_path, inner_expr)
        return None

    def resolve_call(self, file_path: Path, call_node: TSNode) -> Optional[BaseNode]:
        """Resolve call expressions (e.g., get_router()) to domain nodes via factory functions."""
        function_node = call_node.child_by_field_name("function")
        if function_node and function_node.type == ExpressionType.IDENTIFIER:
            func_name = function_node.text.decode("utf-8")
            file_rel = self.to_relative_path(file_path)
            # Try to resolve as factory function
            router = self.symbol_index.resolve_router_factory(file_rel, func_name)
            if router:
                return router
        return None

    def resolve_identifier(self, file_path: Path, identifier_node: TSNode) -> Optional[BaseNode]:
        """Resolve a identifier node to a known domain node (ApplicationNode, RouterNode, etc.) or None."""
        if identifier_node.type != ExpressionType.IDENTIFIER:
            return None

        identifier: str = identifier_node.text.decode("utf-8")
        relative_path: str = self.to_relative_path(file_path)

        # Check cache
        cache_key: Tuple[str, str, str] = (relative_path, identifier, ExpressionType.IDENTIFIER)
        if cache_key in self.resolution_cache:
            return self.resolution_cache[cache_key]

        # Resolve identifier
        result: Optional[BaseNode] = self._resolve(file_path, identifier, relative_path)

        # Cache result (even None to avoid repeated failures)
        self.resolution_cache[cache_key] = result
        return result

    def _resolve(self, file_path: Path, identifier: str, path: str) -> Optional[BaseNode]:
        """Core identifier resolution logic (framework-agnostic, uses strategy)."""
        # Strategy 1: Local instances (uses strategy)
        node: Optional[BaseNode] = self.strategy.find_local_instances(self.symbol_index, path, identifier)
        if node:
            return node

        # Strategy 2: Imported symbol
        resolved: Optional[Tuple[str, str]] = self.import_graph.resolve_name(file_path, identifier)
        if not resolved:
            return None

        source_module, source_symbol = resolved
        lookup_symbol: str = source_symbol if source_symbol else identifier

        # Strategy 3: Module-path lookups using pre-computed index (uses strategy)
        module_paths: Set[str] = self._expand_module_path_candidates(source_module, source_symbol)

        for module_path in module_paths:
            node = self.strategy.find_by_module(self.symbol_index, module_path, lookup_symbol)
            if node:
                return node

        # Strategy 4: Fallback file-based lookup (uses strategy)
        source_file = self.import_graph.file_for_module(source_module)
        if source_file:
            src_rel = self.to_relative_path(source_file)
            sym = source_symbol or identifier
            node = self.strategy.find_by_file(self.symbol_index, src_rel, sym)
            if node:
                return node
        return None

    def resolve_attribute_access(self, file_path: Path, attribute_node: TSNode) -> Optional[BaseNode]:
        """Resolve a attribute access node (e.g., app.router, module.service) to a known domain node or None."""
        if attribute_node.type != ExpressionType.ATTRIBUTE:
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
        file_rel = self.to_relative_path(file_path)

        # Check cache first (Phase 1 optimization)
        cache_key = (file_rel, f"{base_text}.{attribute_name}", ExpressionType.ATTRIBUTE)
        if cache_key in self.resolution_cache:
            return self.resolution_cache[cache_key]

        # First try direct binding (uses submodule checking)
        bound = self.resolve_identifier(file_path, base_identifier)
        if bound:
            self.resolution_cache[cache_key] = bound
            return bound

        # Imported module/package - try module-path lookups with submodule checking
        resolved = self.import_graph.resolve_name(file_path, base_text)
        if not resolved:
            self.resolution_cache[cache_key] = None
            return None
        source_module, source_symbol = resolved

        # Try module-path lookups using pre-computed index (uses strategy)
        module_paths = self._expand_module_path_candidates_for_attribute(source_module, source_symbol, attribute_name)

        for module_path in module_paths:
            node = self.strategy.find_attribute_by_module(self.symbol_index, module_path, attribute_name)
            if node:
                self.resolution_cache[cache_key] = node
                return node

        # Fallback: file-based lookup (uses strategy)
        source_file = self.import_graph.file_for_module(source_module)
        if source_file:
            src_rel = self.to_relative_path(source_file)
            result = self.strategy.find_attribute_by_file(self.symbol_index, src_rel, attribute_name)
            if result:
                self.resolution_cache[cache_key] = result
                return result

        self.resolution_cache[cache_key] = None
        return None

    def _extract_base_identifier(self, node: TSNode) -> Optional[TSNode]:
        """Extract the base identifier from a nested attribute node (e.g., from app.routers.v1 extracts app)."""
        if node.type == ExpressionType.IDENTIFIER:
            return node
        elif node.type == ExpressionType.ATTRIBUTE:
            # Recursively get the object
            object_node = node.child_by_field_name("object")
            if object_node:
                return self._extract_base_identifier(object_node)
        return None

    def resolve_to_type(self, file_path: Path, expr_node: TSNode, node_type: "NodeType") -> Optional[BaseNode]:
        """Resolve expression to a specific node type (framework-agnostic)."""
        resolved = self.resolve_expression(file_path, expr_node)
        if resolved and resolved.type == node_type:
            return resolved
        return None

    def build_module_path_index(self) -> None:
        """Pre-compute module path index (module_prefix -> set of submodules) for O(1) lookups instead of O(n) scans."""
        if not self.import_graph or not hasattr(self.import_graph, "module_to_file"):
            return

        # Clear existing index if rebuilding
        self.module_path_index.clear()

        # Build index from all modules in import graph
        for module_name in self.import_graph.module_to_file.keys():
            parts = module_name.split(".")
            # Build all prefixes: "api.v1.users" -> ["api", "api.v1", "api.v1.users"]
            for i in range(1, len(parts) + 1):
                prefix = ".".join(parts[:i])
                if prefix not in self.module_path_index:
                    self.module_path_index[prefix] = set()
                self.module_path_index[prefix].add(module_name)

    def _expand_module_path_candidates(self, source_module: str, source_symbol: Optional[str]) -> Set[str]:
        """Expand module path candidates using pre-computed index, returning all possible paths where the symbol might be found."""
        module_paths: Set[str] = {source_module}

        if source_symbol:
            # Direct combinations
            module_paths.update([f"{source_module}.{source_symbol.lower()}", f"{source_module}.{source_symbol}"])

            # Get all submodules from pre-computed index (O(1) lookup)
            if source_module in self.module_path_index:
                module_paths.update(self.module_path_index[source_module])

        return module_paths

    def _expand_module_path_candidates_for_attribute(
        self, source_module: str, source_symbol: Optional[str], attribute_name: str
    ) -> Set[str]:
        """Expand module path candidates for attribute access resolution, including attribute-specific path combinations."""
        module_paths: Set[str] = {source_module}

        if source_symbol:
            full_module = f"{source_module}.{source_symbol}"
            module_paths.add(full_module)
            module_paths.update([f"{full_module}.{attribute_name.lower()}", f"{full_module}.{attribute_name}"])
            # Get submodules from pre-computed index
            if full_module in self.module_path_index:
                module_paths.update(self.module_path_index[full_module])
        else:
            module_paths.update([f"{source_module}.{attribute_name.lower()}", f"{source_module}.{attribute_name}"])
            # Get submodules from pre-computed index
            if source_module in self.module_path_index:
                module_paths.update(self.module_path_index[source_module])

        return module_paths

    def invalidate_cache(self) -> None:
        """Invalidate all cached resolution results (call when symbol index or import graph changes)."""
        self.resolution_cache.clear()
        self.to_relative_path.cache_clear()

    @lru_cache(maxsize=10000)
    def to_relative_path(self, file_path: Path) -> str:
        """Convert absolute file path to relative path from project root (cached for performance)."""
        return str(file_path.relative_to(self.project_path))
