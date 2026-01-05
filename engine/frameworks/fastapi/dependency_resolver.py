"""FastAPI Dependency Resolver - Recursively resolves dependency injection chains."""

from pathlib import Path
from typing import List, Set, Optional, Dict
from tree_sitter import Node as TSNode

from engine.models import ExpressionType, FunctionNode
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser import QueryEngine
from engine.ignore import file_to_module_path
from engine.frameworks.base import DependencyResolver as BaseDependencyResolver


class FastAPIDependencyResolver(BaseDependencyResolver):
    """Resolves FastAPI dependency injection chains recursively."""

    def __init__(self, binder: SymbolResolver, query_engine: QueryEngine, project_hash: Optional[str] = None):
        """
        Initialize the dependency resolver.

        Args:
            binder: SymbolResolver instance for symbol resolution
            query_engine: QueryEngine configured for FastAPI queries
            project_hash: Project hash for creating FunctionNode IDs
        """
        self.binder = binder
        self.query_engine = query_engine
        # Use parser from query_engine instead of creating new
        self.parser = query_engine.parser
        # Create a separate query engine for generic queries (finding functions)
        self.generic_query_engine = QueryEngine(self.parser, query_subdirectory="generic")
        self.project_hash = project_hash or "default"

        # Cache to avoid infinite loops and redundant work
        self._dependency_cache: Dict[str, List[FunctionNode]] = {}
        # Cache for function lookups to avoid repeated project-wide searches
        self._function_lookup_cache: Dict[str, Optional[FunctionNode]] = {}

    def resolve_dependency_chain(
        self, provider_node: FunctionNode, depth: int = 0, max_depth: int = 10, visited: Optional[Set[str]] = None
    ) -> List[FunctionNode]:
        """
        Recursively resolve the complete dependency chain starting from a provider function.

        Args:
            provider_node: The function that provides the dependency
            depth: Current recursion depth
            max_depth: Maximum recursion depth to prevent infinite loops
            visited: Set of already visited function IDs to detect circular dependencies

        Returns:
            List of FunctionNode representing the dependency chain (flattened)
        """
        if visited is None:
            visited = set()

        if depth >= max_depth or provider_node.id in visited:
            return []

        # Check cache
        if provider_node.id in self._dependency_cache:
            return self._dependency_cache[provider_node.id]

        # Mark as visited
        visited.add(provider_node.id)

        # Result accumulator
        dependencies: List[FunctionNode] = []

        # Parse the provider function to find Depends() in its parameters
        file_path = Path(provider_node.path)
        if not file_path.is_absolute():
            file_path = self.binder.project_path / file_path

        if not file_path.exists():
            return []

        tree = self.parser.parse_file(file_path)
        if not tree:
            return []

        # Find Depends() calls in this function's parameters
        try:
            # Use FastAPI query engine for depends patterns
            results = self.query_engine.execute_query(tree, "depends", validate_imports=False)

            for result in results:
                depends_node = result.get_capture_node("depends_call") or result.get_capture_node("depends_call_attr")
                if not depends_node:
                    continue

                # Check if this Depends() is within the provider function's line range
                depends_line = depends_node.start_point[0] + 1
                if not (provider_node.start_line <= depends_line <= provider_node.end_line):
                    continue

                # Extract the provider argument from Depends(provider)
                nested_provider = self._extract_provider_from_depends(depends_node, file_path)
                if nested_provider:
                    dependencies.append(nested_provider)

                    # Recursively resolve nested dependencies
                    nested_deps = self.resolve_dependency_chain(nested_provider, depth + 1, max_depth, visited.copy())
                    dependencies.extend(nested_deps)

        except Exception:
            # Silently continue if dependency resolution fails for a provider
            # This prevents one broken dependency from breaking the entire chain
            pass

        # Cache the result
        self._dependency_cache[provider_node.id] = dependencies

        return dependencies

    def extract_provider_from_node(self, node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """Extract provider function from FastAPI Depends() node."""
        args_node = node.child_by_field_name("arguments")
        if not args_node:
            return None

        for child in args_node.children:
            if child.type in ["(", ")", ",", "\n"]:
                continue

            if child.type in ["identifier", "attribute", "call", "await"]:
                provider = self.resolve_provider_from_argument(child, file_path)
                if provider:
                    return provider

        return None

    def _extract_provider_from_depends(self, depends_node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """Extract the provider function from a Depends() call node."""
        return self.extract_provider_from_node(depends_node, file_path)

    def _find_class_init(self, class_node, file_path: Path) -> Optional[FunctionNode]:
        """Find the __init__ method of a class for class-based dependencies."""
        tree = self.parser.parse_file(file_path)
        if not tree:
            return None

        results = self.generic_query_engine.execute_query(tree, "functions", validate_imports=False)
        for result in results:
            func_name = result.get_capture_text("function_name")
            func_node = result.get_capture_node("function")

            if func_name == "__init__" and func_node:
                func_line = func_node.start_point[0] + 1

                # If we have class bounds, verify __init__ is within them
                if hasattr(class_node, "start_line") and hasattr(class_node, "end_line"):
                    if not (class_node.start_line <= func_line <= class_node.end_line):
                        continue

                # Found __init__ (either verified within class bounds, or no bounds available)
                module_name = file_to_module_path(file_path, self.binder.project_path)
                return FunctionNode.from_tree_sitter(
                    node=func_node,
                    file_path=file_path,
                    project_path=self.binder.project_path,
                    project_hash=self.project_hash,
                    module_name=module_name,
                    parent_class=class_node.name,
                )
        return None

    def resolve_provider_from_argument(self, arg_node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """Resolve a dependency provider directly from a function argument node."""
        resolved = self.binder.resolve_expression(file_path, arg_node)

        if isinstance(resolved, FunctionNode):
            return resolved

        # Handle class-based dependencies
        if hasattr(resolved, "name") and hasattr(resolved, "path"):
            return self._find_class_init(resolved, file_path)

        # Unwrap await expressions: await get_db() -> get_db()
        node_to_check = arg_node
        if arg_node.type == ExpressionType.AWAIT and arg_node.named_child_count > 0:
            node_to_check = arg_node.named_child(0)

        # Extract function name from identifier or call
        if node_to_check.type == ExpressionType.IDENTIFIER:
            func_name = node_to_check.text.decode("utf-8", errors="ignore")
            # Skip FastAPI security schemes (HTTPBearer, OAuth2PasswordBearer, etc.)
            if func_name in ("security", "oauth2_scheme", "bearer_scheme"):
                return None
            return self._find_function_in_file(file_path, func_name)
        elif node_to_check.type == ExpressionType.CALL:
            function_node = node_to_check.child_by_field_name("function")
            if function_node and function_node.type == ExpressionType.IDENTIFIER:
                func_name = function_node.text.decode("utf-8", errors="ignore")
                return self._find_function_in_file(file_path, func_name)

        return None

    def _find_function_in_file(self, file_path: Path, function_name: str) -> Optional[FunctionNode]:
        """Find a function by name, searching in imported modules, current file, or project-wide."""
        # Check cache first
        if function_name in self._function_lookup_cache:
            return self._function_lookup_cache[function_name]

        # Strategy 1: Check if function is imported, then search in source file
        resolved = self.binder.import_graph.resolve_name(file_path, function_name)
        if resolved:
            source_module, source_symbol = resolved
            lookup_name = source_symbol if source_symbol else function_name
            source_file = self.binder.import_graph.file_for_module(source_module)
            if source_file:
                func_node = self._search_function_in_file(source_file, lookup_name)
                if func_node:
                    self._function_lookup_cache[function_name] = func_node
                    return func_node

        # Strategy 2: Search in current file
        func_node = self._search_function_in_file(file_path, function_name)
        if func_node:
            self._function_lookup_cache[function_name] = func_node
            return func_node

        # Strategy 3: Search project-wide (last resort)
        from engine.ignore import discover_python_files

        python_files = discover_python_files(self.binder.project_path)
        for py_file in python_files:
            if py_file == file_path:
                continue
            func_node = self._search_function_in_file(py_file, function_name)
            if func_node:
                self._function_lookup_cache[function_name] = func_node
                return func_node

        # Cache None to avoid repeated searches
        self._function_lookup_cache[function_name] = None
        return None

    def _search_function_in_file(self, file_path: Path, function_name: str) -> Optional[FunctionNode]:
        """Search for a function in a specific file."""
        if not file_path.exists():
            return None

        tree = self.parser.parse_file(file_path)
        if not tree:
            return None

        results = self.generic_query_engine.execute_query(tree, "functions", validate_imports=False)
        for result in results:
            func_name = result.get_capture_text("function_name")
            func_node_ts = result.get_capture_node("function")

            if func_name == function_name and func_node_ts:
                module_name = file_to_module_path(file_path, self.binder.project_path)
                return FunctionNode.from_tree_sitter(
                    node=func_node_ts,
                    file_path=file_path,
                    project_path=self.binder.project_path,
                    project_hash=self.project_hash,
                    module_name=module_name,
                )

        return None
