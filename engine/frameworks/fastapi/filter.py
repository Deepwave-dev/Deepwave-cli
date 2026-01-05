"""
FastAPI Filter - Identifies FastAPI-specific patterns in CoreGraph

This filter analyzes the language-agnostic CoreGraph to identify FastAPI-specific patterns.
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from tree_sitter import Node as TSNode

from engine.models import CoreGraph, GenericNode, GenericEdge, GenericNodeType, GenericEdgeType
from engine.frameworks.base import FrameworkFilter, PatternMatcher
from engine.parser import TreeSitterParser, QueryEngine
from engine.parser.parse_cache import ParseCache
from engine.ignore import is_test_file
from engine.frameworks.fastapi.pattern_matcher import FastAPIPatternMatcher


class FastAPIFilter(FrameworkFilter):
    """Identifies FastAPI-specific patterns in a CoreGraph."""

    def __init__(self, project_hash: str, project_path: Path, parse_cache: ParseCache, import_graph):
        """Initialize the FastAPI filter."""
        self.project_hash = project_hash
        self.project_path = project_path
        self.parse_cache = parse_cache
        self.import_graph = import_graph
        self.parser = parse_cache.parser
        self.query_engine = QueryEngine(self.parser, query_subdirectory="fastapi")
        self.pattern_matcher: PatternMatcher = FastAPIPatternMatcher(import_graph, is_test_file)

        # Storage for identified patterns (GenericNodes that match FastAPI patterns)
        self.applications: List[GenericNode] = []
        self.routers: List[GenericNode] = []
        self.endpoints: List[Tuple[GenericNode, GenericNode]] = []  # (function, decorator)
        self.services: List[GenericNode] = []
        self.methods: List[GenericNode] = []
        self.entry_points: List[GenericNode] = []
        self.functions: List[GenericNode] = []
        self.dependencies: List[Tuple[GenericNode, TSNode, str]] = []  # (endpoint/router node, Depends() TSNode, scope)

    def filter(self, core_graph: CoreGraph) -> None:
        """
        Analyze the CoreGraph to identify FastAPI-specific patterns.

        Args:
            core_graph: The language-agnostic CoreGraph to analyze
        """
        # Find FastAPI patterns in order of dependencies
        self._find_applications(core_graph)
        self._find_routers(core_graph)
        self._find_endpoints(core_graph)
        self._find_dependencies(core_graph)
        self._find_services(core_graph)
        self._find_methods(core_graph)
        self._find_functions(core_graph)
        self._find_entry_points(core_graph)

    def _validate_import(self, node: GenericNode, core_graph: CoreGraph, required_imports: List[str]) -> bool:
        """Validate required imports using semantic resolution."""
        for required in required_imports:
            resolved = self.import_graph.resolve_name(node.file_path, required)
            if resolved and resolved[0]:
                return True
        return False

    def _find_applications(self, core_graph: CoreGraph) -> None:
        """Find FastAPI application instantiations."""
        self._find_and_validate(
            core_graph,
            GenericNodeType.ASSIGNMENT,
            self.pattern_matcher.is_application_instance,
            self.pattern_matcher.get_application_imports,
            self.applications,
        )

    def _find_routers(self, core_graph: CoreGraph) -> None:
        """Find APIRouter instantiations."""
        self._find_and_validate(
            core_graph,
            GenericNodeType.ASSIGNMENT,
            self.pattern_matcher.is_routing_configuration,
            self.pattern_matcher.get_routing_imports,
            self.routers,
        )

    def _find_endpoints(self, core_graph: CoreGraph) -> None:
        """
        Find FastAPI endpoint functions in the CoreGraph.

        Pattern: function decorated with @router.get/post/put/delete/patch
        Example: @router.get("/users") def get_users(): ...
        """
        functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)

        for func_node in functions:
            # Find DECORATES edges pointing to this function
            decorates_edges = core_graph.get_edges_to_node(func_node.id)

            for edge in decorates_edges:
                if edge.edge_type != GenericEdgeType.DECORATES:
                    continue

                decorator_node = core_graph.get_node(edge.source_id)
                if not decorator_node:
                    continue

                # Check if this is a request handler
                handler_info = self.pattern_matcher.is_request_handler(func_node, core_graph)
                if handler_info:
                    self.endpoints.append((func_node, decorator_node))
                    break

    def _find_services(self, core_graph: CoreGraph) -> None:
        """
        Find service classes in the CoreGraph.

        Pattern: class with methods that looks like a service
        Uses heuristics similar to ServiceNodeExtractorTreeSitter
        """
        classes = core_graph.get_nodes_by_type(GenericNodeType.CLASS)

        for class_node in classes:
            if self._is_service_class(class_node, core_graph):
                self.services.append(class_node)

    def _find_methods(self, core_graph: CoreGraph) -> None:
        """
        Find methods belonging to service classes.

        Pattern: methods (functions inside classes) that belong to identified services
        """
        for service_node in self.services:
            # Get children of this service class
            children = core_graph.get_children(service_node.id)

            for child in children:
                if child.node_type == GenericNodeType.METHOD:
                    self.methods.append(child)

    def _find_functions(self, core_graph: CoreGraph) -> None:
        """
        Find all standalone functions in the CoreGraph for the call graph.

        Note: Methods are tracked separately in self.methods. This only includes
        standalone functions (not methods inside classes).
        """
        standalone_functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)
        self.functions = list(standalone_functions)

    def _find_dependencies(self, core_graph: CoreGraph) -> None:
        """
        Find FastAPI Depends() patterns in endpoint functions and router configurations.

        Detects:
        - Function-level dependencies: def endpoint(db = Depends(get_db))
        - Router-level dependencies: APIRouter(dependencies=[Depends(verify_token)])
        """
        # Track all detected dependencies
        detected_dependencies = []

        # 1. Find function-level dependencies in endpoints
        for func_node, _ in self.endpoints:
            if not func_node.file_path.exists():
                continue

            # Use cache or parse if not cached
            tree = self.parse_cache.get_tree(func_node.file_path)
            if not tree:
                tree = self.parser.parse_file(func_node.file_path)
                if tree:
                    self.parse_cache.store_tree(func_node.file_path, tree)
            if not tree:
                continue

            # Use the depends query to find Depends() patterns
            try:
                results = self.query_engine.execute_query(tree, "depends", validate_imports=False)

                for result in results:
                    # Check if this Depends() is within the current endpoint function
                    depends_node = result.get_capture_node("depends_call") or result.get_capture_node(
                        "depends_call_attr"
                    )
                    if not depends_node:
                        continue

                    # Check if the depends_node is within the function's line range
                    depends_line = depends_node.start_point[0] + 1
                    if func_node.start_line <= depends_line <= func_node.end_line:
                        # Validate that Depends is imported
                        if self._validate_depends_import(func_node.file_path, core_graph):
                            detected_dependencies.append((func_node, depends_node, "function"))
            except Exception:
                pass

        # 2. Find router-level dependencies
        for router_node in self.routers:
            if not router_node.file_path.exists():
                continue

            # Use cache if available, otherwise parse
            if self.parse_cache:
                tree = self.parse_cache.get_tree(router_node.file_path)
                if not tree:
                    tree = self.parser.parse_file(router_node.file_path)
                    if tree:
                        self.parse_cache.store_tree(router_node.file_path, tree)
            else:
                tree = self.parser.parse_file(router_node.file_path)
            if not tree:
                continue

            try:
                results = self.query_engine.execute_query(tree, "depends", validate_imports=False)

                for result in results:
                    # Check for router dependencies keyword argument
                    kwarg_name = result.get_capture_text("kwarg_name")
                    if kwarg_name == "dependencies":
                        depends_node = result.get_capture_node("depends_call")
                        if depends_node:
                            # Check if this is within the router's line range
                            depends_line = depends_node.start_point[0] + 1
                            if router_node.start_line <= depends_line <= router_node.end_line:
                                if self._validate_depends_import(router_node.file_path, core_graph):
                                    detected_dependencies.append((router_node, depends_node, "router"))
            except Exception:
                pass

        self.dependencies = detected_dependencies

    def _find_entry_points(self, core_graph: CoreGraph) -> None:
        """Find entry point functions that instantiate services (excludes endpoints and test files)."""
        endpoint_function_ids = {func_node.id for func_node, _ in self.endpoints}
        calls_edges = core_graph.get_edges_by_type(GenericEdgeType.CALLS)
        called_function_ids = {edge.target_id for edge in calls_edges}

        candidate_entry_points = []
        for func in self.functions:
            if func.node_type == GenericNodeType.METHOD:
                continue
            if self._is_test_file(func.file_path):
                continue
            if func.id in endpoint_function_ids:
                continue
            if func.id not in called_function_ids:
                candidate_entry_points.append(func)

        for candidate in candidate_entry_points:
            if self._instantiates_service(candidate, core_graph):
                self.entry_points.append(candidate)

    # Helper methods for pattern detection

    def _is_service_class(self, class_node: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if class is a service (includes infrastructure, excludes model classes)."""
        # Exclude model classes: Pydantic models, dataclasses, or classes with 0 methods
        if self._is_pydantic_model(class_node) or self._is_dataclass(class_node, core_graph):
            return False

        # Exclude abstract base classes (ABC)
        if self._is_abstract_base_class(class_node):
            return False

        children = core_graph.get_children(class_node.id)
        methods = [c for c in children if c.node_type == GenericNodeType.METHOD]

        # Exclude classes with no instance methods (only static/abstract methods)
        if not methods or self._has_only_static_methods(class_node, methods, core_graph):
            return False

        # Include any class with instance methods (both instantiated services and infrastructure classes)
        return True

    def _is_abstract_base_class(self, class_node: GenericNode) -> bool:
        """Check if class is an abstract base class (inherits from ABC)."""
        if not class_node.source_code:
            return False

        # Check first line for ABC inheritance
        lines = class_node.source_code.split("\n")
        first_line = lines[0] if lines else class_node.source_code

        return "(ABC)" in first_line or ", ABC)" in first_line or "ABC," in first_line

    def _has_only_static_methods(
        self, class_node: GenericNode, methods: List[GenericNode], core_graph: CoreGraph
    ) -> bool:
        """Check if class has only static methods (no instance methods)."""
        if not methods:
            return True

        # Check if all methods are static or abstract
        file_nodes = core_graph.get_nodes_by_file(class_node.file_path)
        decorators = {n.start_line: n for n in file_nodes if n.node_type == GenericNodeType.DECORATOR}

        instance_method_count = 0
        for method in methods:
            # Check if method has @staticmethod or @abstractmethod decorator
            is_static = False
            is_abstract = False

            # Check decorators near this method
            for line_num, decorator in decorators.items():
                if abs(line_num - method.start_line) <= 2:
                    decorator_name = decorator.name or ""
                    if "staticmethod" in decorator_name.lower():
                        is_static = True
                    if "abstractmethod" in decorator_name.lower():
                        is_abstract = True

            # If method is not static and not abstract, it's an instance method
            if not is_static and not is_abstract:
                instance_method_count += 1

        # If no instance methods, exclude this class
        return instance_method_count == 0

    def _is_class_instantiated(self, class_node: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if class is instantiated anywhere in the codebase."""
        class_name = class_node.name
        pattern = f"{class_name}("

        assignments = core_graph.get_nodes_by_type(GenericNodeType.ASSIGNMENT)
        for assignment in assignments:
            if assignment.source_code and pattern in assignment.source_code:
                return True

        functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)
        methods = core_graph.get_nodes_by_type(GenericNodeType.METHOD)
        for func in list(functions) + list(methods):
            if func.source_code and pattern in func.source_code:
                return True

        return False

    def _is_pydantic_model(self, class_node: GenericNode) -> bool:
        """Check if class inherits from Pydantic BaseModel."""
        if not class_node.source_code:
            return False

        # Only check the first line (class definition line) to avoid false positives
        # from imports or comments elsewhere in the source_code
        lines = class_node.source_code.split("\n")
        first_line = lines[0] if lines else class_node.source_code

        pydantic_patterns = ["(BaseModel)", "(BaseModel,", ", BaseModel)", ", BaseModel,", "pydantic.BaseModel"]
        return any(pattern in first_line for pattern in pydantic_patterns)

    def _is_dataclass(self, class_node: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if class is decorated with @dataclass."""
        try:
            # Read the file to check for @dataclass decorator before the class
            if not class_node.file_path.exists():
                return False

            with open(class_node.file_path, "r", encoding="utf-8") as f:
                file_lines = f.readlines()

            # Check lines before the class definition (decorator is typically 1-2 lines before)
            start_line = class_node.start_line - 1  # Convert to 0-indexed
            for i in range(max(0, start_line - 3), start_line + 1):
                if i < len(file_lines) and "@dataclass" in file_lines[i].lower():
                    return True
        except Exception:
            pass

        # Fallback: check source_code if available
        if class_node.source_code:
            lines = class_node.source_code.split("\n")
            for line in lines[:5]:
                if "@dataclass" in line.lower():
                    return True

        # Also check file nodes for decorator nodes (fallback)
        file_nodes = core_graph.get_nodes_by_file(class_node.file_path)
        decorators = [n for n in file_nodes if n.node_type == GenericNodeType.DECORATOR]
        for decorator in decorators:
            if "dataclass" in (decorator.name or "").lower() and abs(decorator.start_line - class_node.start_line) <= 2:
                return True
        return False

    def _instantiates_service(self, func: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if function instantiates any service."""
        if not func.source_code:
            return False
        return any(f"{service.name}(" in func.source_code for service in self.services)

    def _is_test_file(self, file_path: Path) -> bool:
        """Check if file is a test file."""
        return is_test_file(file_path)

    def _validate_depends_import(self, file_path: Path, core_graph: CoreGraph) -> bool:
        """Validate that Depends is imported using semantic resolution."""
        resolved = self.import_graph.resolve_name(file_path, "Depends")
        if not resolved:
            return False
        module, _ = resolved
        required_modules = self.pattern_matcher.get_dependency_imports()
        return module and any(req in module for req in required_modules)
