"""Flask edge discoverer for blueprint registration relationships."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node as TSNode

from engine.models import GraphEdge, EdgeRelation, ApplicationNode, RouterNode
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser.query_engine import QueryEngine
from engine.parser.parse_cache import ParseCache
from engine.frameworks.flask.filter import FlaskFilter
from engine.frameworks.base import EdgeDiscoverer
from engine.ignore import discover_python_files


class FlaskEdgeDiscoverer(EdgeDiscoverer):
    """Discovers app → blueprint registration edges."""

    def __init__(
        self,
        flask_filter: FlaskFilter,
        binder: SymbolResolver,
        query_engine: QueryEngine,
        parse_cache: ParseCache,
        project_hash: str,
        generic_to_domain_id: dict,
    ):
        self.filter = flask_filter
        self.binder = binder
        self.query_engine = query_engine
        self.parse_cache = parse_cache
        self.project_hash = project_hash
        self.generic_to_domain_id = generic_to_domain_id

    def discover(self) -> List[GraphEdge]:
        """Discover all blueprint registration edges."""
        edges = []
        python_files = discover_python_files(self.binder.project_path)

        for file_path in python_files:
            file_edges = self._find_registrations_in_file(file_path)
            edges.extend(file_edges)

        return edges

    def _find_registrations_in_file(self, file_path: Path) -> List[GraphEdge]:
        """Find all app.register_blueprint calls in a file."""
        edges = []
        tree = self.parse_cache.get_tree(file_path)
        if not tree:
            tree = self.parse_cache.parser.parse_file(file_path)
            if tree:
                self.parse_cache.store_tree(file_path, tree)
            else:
                return edges

        # Query for register_blueprint calls
        # Pattern: app.register_blueprint(blueprint)
        query_string = """
        (call
          function: (attribute
            object: (identifier) @object_var
            attribute: (identifier) @method_name
          )
          arguments: (argument_list) @args
        )
        """
        results = self.query_engine.execute_query_string(tree, query_string, "register_blueprint_calls")

        for result in results:
            method_name_node = result.captures.get("method_name")
            if not method_name_node or method_name_node.text.decode() != "register_blueprint":
                continue

            # Resolve object (should be an app instance)
            object_var_node = result.captures.get("object_var")

            # Try to resolve as application
            resolved = self.binder.resolve_expression(file_path, object_var_node)
            source_id = None

            if isinstance(resolved, ApplicationNode):
                # Find the GenericNode for this application
                source_id = self._match_app_to_generic(resolved)

            if not source_id:
                continue

            # Resolve blueprint argument
            args_node = result.captures.get("args")
            target_blueprint = self._resolve_blueprint_argument(args_node, file_path)

            if not target_blueprint:
                continue

            # Match resolved RouterNode to GenericNode in filter
            target_id = self._match_blueprint_to_generic(target_blueprint)

            if not target_id:
                continue

            if target_id == source_id:  # Skip self-loops
                continue

            edge = self._create_includes_edge(source_id, target_id)
            if edge:
                edges.append(edge)

        return edges

    def _resolve_blueprint_argument(self, args_node: TSNode, file_path: Path) -> Optional[RouterNode]:
        """Resolve blueprint argument from argument list."""
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
                # Only try first positional argument (blueprint is always first arg in register_blueprint)
                break

        # Try keyword argument: blueprint=user_bp
        for child in args_node.children:
            if child.type == "keyword_argument":
                keyword_name = child.child_by_field_name("name")
                if keyword_name and keyword_name.text.decode() == "blueprint":
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

    def _match_blueprint_to_generic(self, resolved_blueprint: RouterNode) -> Optional[str]:
        """Match a resolved RouterNode to a GenericNode in the filter."""
        # Strategy 1: Match by domain ID (direct match)
        # The resolved_blueprint.id should be in generic_to_domain_id.values()
        if resolved_blueprint.id in self.generic_to_domain_id.values():
            return resolved_blueprint.id

        # Strategy 2: Match by router_var and file path
        if hasattr(resolved_blueprint, "router_var") and hasattr(resolved_blueprint, "path"):
            resolved_path = resolved_blueprint.path
            resolved_var = resolved_blueprint.router_var

            for bp_node in self.filter.blueprints:
                bp_id = self.generic_to_domain_id.get(bp_node.id)
                if not bp_id:
                    continue

                # Convert bp_node.file_path to relative path string for comparison
                bp_path = str(bp_node.file_path.relative_to(self.binder.project_path))

                # Match by blueprint var and path
                # bp_node.name is the variable name (e.g., "api_bp")
                # resolved_var is also the variable name
                if bp_node.name == resolved_var and bp_path == resolved_path:
                    return bp_id

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
