"""FastAPI edge discoverer for includes relationships."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node as TSNode

from engine.models import GraphEdge, EdgeRelation, ApplicationNode, RouterNode
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser.query_engine import QueryEngine
from engine.parser.parse_cache import ParseCache
from engine.frameworks.fastapi.filter import FastAPIFilter
from engine.frameworks.base import EdgeDiscoverer
from engine.ignore import discover_python_files


class FastAPIEdgeDiscoverer(EdgeDiscoverer):
    """Discovers app → router and router → router includes edges."""

    def __init__(
        self,
        fastapi_filter: FastAPIFilter,
        binder: SymbolResolver,
        query_engine: QueryEngine,
        parse_cache: ParseCache,
        project_hash: str,
        generic_to_domain_id: dict,
    ):
        self.filter = fastapi_filter
        self.binder = binder
        self.query_engine = query_engine
        self.parse_cache = parse_cache
        self.project_hash = project_hash
        self.generic_to_domain_id = generic_to_domain_id

    def discover(self) -> List[GraphEdge]:
        """Discover all includes edges."""
        edges = []
        python_files = discover_python_files(self.binder.project_path)

        for file_path in python_files:
            file_edges = self._find_includes_in_file(file_path)
            edges.extend(file_edges)

        return edges

    def _find_includes_in_file(self, file_path: Path) -> List[GraphEdge]:
        """Find all include_router calls in a file."""
        edges = []
        tree = self.parse_cache.get_tree(file_path)
        if not tree:
            tree = self.parse_cache.parser.parse_file(file_path)
            if tree:
                self.parse_cache.store_tree(file_path, tree)
            else:
                return edges

        # Query for include_router calls
        query_string = """
        (call
          function: (attribute
            object: (identifier) @object_var
            attribute: (identifier) @method_name
          )
          arguments: (argument_list) @args
        )
        """
        results = self.query_engine.execute_query_string(tree, query_string, "include_router_calls")

        for result in results:
            method_name_node = result.captures.get("method_name")
            if not method_name_node or method_name_node.text.decode() != "include_router":
                continue

            # Resolve object (could be app or router)
            object_var_node = result.captures.get("object_var")

            # Try to resolve as application first
            resolved = self.binder.resolve_expression(file_path, object_var_node)
            source_id = None

            if isinstance(resolved, ApplicationNode):
                # Find the GenericNode for this application
                source_id = self._match_app_to_generic(resolved)
            elif isinstance(resolved, RouterNode):
                # Try to resolve as router
                source_id = self._match_router_to_generic(resolved)

            if not source_id:
                continue

            # Resolve router argument
            args_node = result.captures.get("args")
            target_router = self._resolve_router_argument(args_node, file_path)

            if not target_router:
                continue

            # Match resolved RouterNode to GenericNode in filter
            target_id = self._match_router_to_generic(target_router)

            if not target_id:
                continue

            if target_id == source_id:  # Skip self-loops
                continue

            edge = self._create_includes_edge(source_id, target_id)
            if edge:
                edges.append(edge)

        return edges

    def _resolve_router_argument(self, args_node: TSNode, file_path: Path) -> Optional[RouterNode]:
        """Resolve router argument from argument list."""
        if not args_node or args_node.type != "argument_list":
            return None

        # Filter out punctuation tokens: '(', ')', ','
        # Also filter out keyword arguments for positional search
        def is_valid_positional_argument(node: TSNode) -> bool:
            return node.type not in ("(", ")", ",") and node.type != "keyword_argument"

        # Try positional argument first (most common)
        # Find first non-punctuation, non-keyword argument
        for child in args_node.children:
            if is_valid_positional_argument(child):
                resolved = self.binder.resolve_expression(file_path, child)
                if isinstance(resolved, RouterNode):
                    return resolved
                # Only try first positional argument (router is always first arg in include_router)
                break

        # Try keyword argument: router=user_router
        for child in args_node.children:
            if child.type == "keyword_argument":
                keyword_name = child.child_by_field_name("name")
                if keyword_name and keyword_name.text.decode() == "router":
                    value = child.child_by_field_name("value")
                    if value:
                        resolved = self.binder.resolve_expression(file_path, value)
                        if isinstance(resolved, RouterNode):
                            return resolved

        return None

    def _match_app_to_generic(self, resolved_app: ApplicationNode) -> Optional[str]:
        """Match a resolved ApplicationNode to a GenericNode in the filter."""
        # Strategy 1: Match by domain ID (direct match)
        if resolved_app.id in self.generic_to_domain_id.values():
            return resolved_app.id

        # Strategy 2: Match by app_var and file path
        if hasattr(resolved_app, "app_var") and hasattr(resolved_app, "path"):
            resolved_path = resolved_app.path
            resolved_var = resolved_app.app_var

            for app_node in self.filter.applications:
                app_id = self.generic_to_domain_id.get(app_node.id)
                if not app_id:
                    continue

                app_path = str(app_node.file_path.relative_to(self.binder.project_path))

                # Match by app_var and path
                # app_node.name is the variable name (e.g., "app")
                if app_node.name == resolved_var and app_path == resolved_path:
                    return app_id

        return None

    def _match_router_to_generic(self, resolved_router: RouterNode) -> Optional[str]:
        """Match a resolved RouterNode to a GenericNode in the filter."""
        # Strategy 1: Match by domain ID (direct match)
        # The resolved_router.id should be in generic_to_domain_id.values()
        if resolved_router.id in self.generic_to_domain_id.values():
            return resolved_router.id

        # Strategy 2: Match by router_var and file path
        if hasattr(resolved_router, "router_var") and hasattr(resolved_router, "path"):
            resolved_path = resolved_router.path
            resolved_var = resolved_router.router_var

            for router_node in self.filter.routers:
                router_id = self.generic_to_domain_id.get(router_node.id)
                if not router_id:
                    continue

                # Convert router_node.file_path to relative path string for comparison
                router_path = str(router_node.file_path.relative_to(self.binder.project_path))

                # Match by router_var and path
                # router_node.name is the variable name (e.g., "api_router")
                # resolved_var is also the variable name
                if router_node.name == resolved_var and router_path == resolved_path:
                    return router_id

        return None

    def _create_includes_edge(self, src_id: str, dst_id: str) -> Optional[GraphEdge]:
        """Create an includes edge if both nodes exist."""
        # Verify both nodes are in our domain graph
        if src_id not in self.generic_to_domain_id.values():
            return None
        if dst_id not in self.generic_to_domain_id.values():
            return None

        return GraphEdge(
            id=f"includes.{self.project_hash}.{src_id}.{dst_id}",
            src_id=src_id,
            dst_id=dst_id,
            relation=EdgeRelation.includes,
            project_hash=self.project_hash,
        )
