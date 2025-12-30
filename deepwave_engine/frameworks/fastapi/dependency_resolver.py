"""
FastAPI Dependency Resolver - Recursively resolves dependency injection chains

This resolver analyzes Depends() calls to build complete dependency chains,
handling nested dependencies, class-based dependencies, and edge cases.
"""

from pathlib import Path
from typing import List, Set, Optional, Tuple, Dict
from loguru import logger
from tree_sitter import Node as TSNode

from deepwave_engine.models import FunctionNode
from deepwave_engine.binder.binder_treesitter import BinderTreeSitter
from deepwave_engine.binder.expression_resolver import ExpressionResolver
from deepwave_engine.parser import TreeSitterParser, QueryEngine
from deepwave_engine.ignore import file_to_module_path


class DependencyResolver:
    """Resolves FastAPI dependency injection chains recursively."""

    def __init__(self, binder: BinderTreeSitter, query_engine: QueryEngine):
        """
        Initialize the dependency resolver.

        Args:
            binder: BinderTreeSitter instance for symbol resolution
            query_engine: QueryEngine configured for FastAPI queries
        """
        self.binder = binder
        self.query_engine = query_engine
        self.parser = TreeSitterParser("python")
        self.resolver = ExpressionResolver(binder)
        # Create a separate query engine for generic queries (finding functions)
        self.generic_query_engine = QueryEngine(self.parser, query_subdirectory="generic")

        # Cache to avoid infinite loops and redundant work
        self._dependency_cache: Dict[str, List[FunctionNode]] = {}

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

        # Base case: max depth reached
        if depth >= max_depth:
            logger.warning(f"Max dependency depth reached for {provider_node.name}")
            return []

        # Base case: circular dependency detected
        if provider_node.id in visited:
            logger.warning(f"Circular dependency detected: {provider_node.name}")
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

        except Exception as e:
            logger.debug(f"Error resolving dependencies for {provider_node.name}: {e}")

        # Cache the result
        self._dependency_cache[provider_node.id] = dependencies

        return dependencies

    def _extract_provider_from_depends(self, depends_node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """
        Extract the provider function from a Depends() call node.

        Args:
            depends_node: Tree-sitter node representing the Depends() call
            file_path: File containing the Depends() call

        Returns:
            FunctionNode of the provider, or None if it cannot be resolved
        """
        # Get the arguments node from Depends(...)
        args_node = depends_node.child_by_field_name("arguments")
        if not args_node:
            return None

        # Find the first argument (the provider)
        for child in args_node.children:
            if child.type in ["identifier", "attribute", "call"]:
                # Use the same resolution logic as resolve_provider_from_argument
                # which includes the fallback to direct function lookup
                provider = self.resolve_provider_from_argument(child, file_path)
                if provider:
                    return provider

                break

        return None

    def _find_class_init(self, class_node, file_path: Path) -> Optional[FunctionNode]:
        """
        Find the __init__ method of a class for class-based dependencies.

        Args:
            class_node: The class node
            file_path: File containing the class

        Returns:
            FunctionNode representing __init__, or None
        """
        try:
            tree = self.parser.parse_file(file_path)
            if not tree:
                return None

            # Find all function definitions using generic query engine
            results = self.generic_query_engine.execute_query(tree, "functions", validate_imports=False)

            for result in results:
                func_name = result.get_capture_text("function_name")
                func_node = result.get_capture_node("function")

                if func_name == "__init__" and func_node:
                    # Check if this __init__ is within the class's line range
                    func_line = func_node.start_point[0] + 1
                    if hasattr(class_node, "start_line") and hasattr(class_node, "end_line"):
                        if class_node.start_line <= func_line <= class_node.end_line:
                            # Create a FunctionNode for __init__
                            from deepwave_engine.ignore import file_to_module_path

                            module_name = file_to_module_path(file_path, self.binder.project_path)
                            return FunctionNode.from_tree_sitter(
                                node=func_node,
                                file_path=file_path,
                                project_path=self.binder.project_path,
                                project_hash=self.binder.project_path.name,
                                module_name=module_name,
                                parent_class=class_node.name,
                            )
        except Exception as e:
            logger.debug(f"Error finding __init__ for class: {e}")

        return None

    def resolve_provider_from_argument(self, arg_node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """
        Resolve a dependency provider directly from a function argument node.

        This is a convenience method for resolving Depends() arguments during mapping.

        Args:
            arg_node: Tree-sitter node of the argument (inside Depends(...))
            file_path: File containing the argument

        Returns:
            FunctionNode of the provider, or None
        """
        resolved = self.resolver.resolve(arg_node, file_path)

        if isinstance(resolved, FunctionNode):
            return resolved

        # Handle class-based dependencies
        if hasattr(resolved, "name") and hasattr(resolved, "path"):
            return self._find_class_init(resolved, file_path)

        # If resolution failed, try to find the function directly in the file
        if arg_node.type == "identifier":
            func_name = arg_node.text.decode("utf-8", errors="ignore")
            func_node = self._find_function_in_file(file_path, func_name)
            if func_node:
                return func_node

        return None

    def _find_function_in_file(self, file_path: Path, function_name: str) -> Optional[FunctionNode]:
        """
        Directly find a function in a file by name.

        This is a fallback when ExpressionResolver can't find the function.
        """
        try:
            tree = self.parser.parse_file(file_path)
            if not tree:
                return None

            # Find all functions using generic query engine
            results = self.generic_query_engine.execute_query(tree, "functions", validate_imports=False)

            for result in results:
                func_name = result.get_capture_text("function_name")
                func_node_ts = result.get_capture_node("function")

                if func_name == function_name and func_node_ts:
                    # Create a FunctionNode

                    module_name = file_to_module_path(file_path, self.binder.project_path)
                    return FunctionNode.from_tree_sitter(
                        node=func_node_ts,
                        file_path=file_path,
                        project_path=self.binder.project_path,
                        project_hash=self.binder.project_path.name,
                        module_name=module_name,
                    )
        except Exception as e:
            logger.debug(f"Error in _find_function_in_file: {e}")

        return None
