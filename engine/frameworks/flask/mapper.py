"""Flask Domain Mapper - Maps GenericNodes to Flask-specific domain models.

This mapper takes filtered GenericNodes from FlaskFilter and creates GraphNodes
(ApplicationNode, RouterNode, EndpointNode, ServiceClassNode, etc.) and GraphEdges.

Phase 2: Node mapping (COMPLETE)
Phase 3: Complete edge mapping (COMPLETE)
"""

from pathlib import Path
from typing import List, Dict, Optional, Tuple
from tree_sitter import Node as TSNode

from engine.models import CoreGraph, GenericNode, GenericNodeType, GenericEdgeType, GraphNode, GraphEdge, EdgeRelation, ExpressionType
from engine.models import (
    ApplicationNode,
    RouterNode,
    EndpointNode,
    ServiceClassNode,
    MethodNode,
    FunctionNode,
    EntryPointNode,
)
from engine.frameworks.flask.filter import FlaskFilter
from engine.frameworks.flask.node_mapper import FlaskNodeMapper
from engine.frameworks.base import DomainMapper
from engine.graph.call_graph import CallGraphResult
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser.query_engine import QueryEngine
from engine.parser.parse_cache import ParseCache


class FlaskDomainMapper(DomainMapper):
    """Maps GenericNodes from CoreGraph to Flask-specific domain models.
    
    Takes filtered GenericNodes and creates GraphNodes (ApplicationNode, RouterNode, etc.)
    and GraphEdges (includes, has_endpoint, calls, contains, etc.).
    
    Phase 2 Implementation: Node mapping only
    Phase 3 Implementation: Complete edge mapping
    """

    def __init__(
        self,
        core_graph: CoreGraph,
        flask_filter: FlaskFilter,
        project_hash: str,
        call_graph_result: Optional[CallGraphResult] = None,
        binder: Optional[SymbolResolver] = None,
        query_engine: Optional[QueryEngine] = None,
    ):
        self.core_graph = core_graph
        self.filter = flask_filter
        self.project_hash = project_hash
        self.call_graph_result = call_graph_result
        self.binder = binder
        self.query_engine = query_engine

        # Output
        self.nodes: List[GraphNode] = []
        self.edges: List[GraphEdge] = []

        # Mapping from GenericNode ID to GraphNode ID
        self.generic_to_domain_id: Dict[str, str] = {}

        # Optimized lookup for function nodes: (path_norm, name, line) -> id
        self.function_lookup: Dict[Tuple[str, str, int], str] = {}

        # Node mapper for framework-specific node creation
        self.node_mapper = FlaskNodeMapper(project_hash, core_graph.project_path)

    def _create_edge(self, src_id: str, dst_id: str, relation: EdgeRelation, edge_type: str) -> GraphEdge:
        """Create a graph edge with standard ID format."""
        return GraphEdge(
            id=f"{edge_type}.{src_id}.{dst_id}",
            src_id=src_id,
            dst_id=dst_id,
            relation=relation,
            project_hash=self.project_hash,
        )

    def map(self) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Map filtered GenericNodes to domain models.
        
        Phase 2: Map nodes only (no edges)
        Phase 3: Add complete edge mapping
        """
        # Map nodes in dependency order
        self._map_applications()
        self._map_blueprints()
        
        # Index apps and blueprints in SymbolIndex BEFORE mapping endpoints (Phase 3+)
        if self.binder:
            app_nodes = [n for n in self.nodes if isinstance(n, ApplicationNode)]
            blueprint_nodes = [n for n in self.nodes if isinstance(n, RouterNode)]
            self.binder.symbol_index.index_applications(app_nodes)
            self.binder.symbol_index.index_routers(blueprint_nodes)
        
        self._map_endpoints()
        
        # Build function lookup from call graph for dependency resolution
        if self.call_graph_result:
            for generic_func in self.call_graph_result.function_nodes:
                rel_path = str(generic_func.file_path.relative_to(self.core_graph.project_path))
                path_norm = rel_path.replace("\\", "/")
                # Create temporary ID for lookup (will be created properly by _map_functions)
                temp_id = f"function.{self.project_hash}.{generic_func.id.split(':')[-1]}"
                self.function_lookup[(path_norm, generic_func.name, generic_func.start_line)] = temp_id
        
        self._map_services()
        self._map_methods()
        self._map_functions()
        self._map_entry_points()
        
        # Extended patterns
        self._map_methodview_endpoints()
        self._map_extensions()
        
        # Phase 3: Edge mapping
        self._map_edges()
        
        # Extended edges
        self._map_extension_initialization_edges()
        
        # Add call graph edges if available
        if self.call_graph_result:
            all_node_ids = {node.id for node in self.nodes}
            entry_point_ids = {
                self.generic_to_domain_id.get(ep.id)
                for ep in self.filter.entry_points
                if self.generic_to_domain_id.get(ep.id)
            }
            blueprint_ids = {
                self.generic_to_domain_id.get(bp.id) 
                for bp in self.filter.blueprints 
                if self.generic_to_domain_id.get(bp.id)
            }
            application_ids = {
                self.generic_to_domain_id.get(a.id)
                for a in self.filter.applications
                if self.generic_to_domain_id.get(a.id)
            }
            endpoint_ids = set()
            for func_node, _ in self.filter.endpoints:
                ep_id = self.generic_to_domain_id.get(func_node.id)
                if ep_id:
                    endpoint_ids.add(ep_id)
            
            # Filter call graph edges to only include valid edges
            valid_call_edges = []
            for edge in self.call_graph_result.call_edges:
                # Check if both nodes exist
                if edge.src_id not in all_node_ids or edge.dst_id not in all_node_ids:
                    continue
                
                # Skip edges from/to certain node types
                if (
                    edge.src_id in entry_point_ids
                    or edge.src_id in blueprint_ids
                    or edge.src_id in application_ids
                    or edge.src_id in endpoint_ids
                ):
                    continue
                if edge.dst_id in blueprint_ids or edge.dst_id in application_ids or edge.dst_id in endpoint_ids:
                    continue
                
                valid_call_edges.append(edge)
            
            self.edges.extend(valid_call_edges)
        
        return self.nodes, self.edges

    def _get_unique_id_from_generic(self, generic_id: str) -> str:
        """Extract a unique identifier from a generic node ID.
        
        Generic IDs are like "project_hash:node_type:hash123"
        """
        parts = generic_id.split(":")
        if len(parts) >= 3:
            return parts[2]  # Return the hash portion
        # Fallback: use the full ID if format is unexpected
        return generic_id.replace(":", "_")

    def _map_applications(self) -> None:
        """Map GenericNode applications to ApplicationNode.
        
        Example: app = Flask(__name__) -> ApplicationNode
        """
        for generic_node in self.filter.applications:
            node = self.node_mapper.map_entry_point(
                generic_node, 
                self.project_hash, 
                self.core_graph.project_path
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_blueprints(self) -> None:
        """Map GenericNode blueprints to RouterNode.
        
        Example: bp = Blueprint('users', __name__) -> RouterNode
        
        Note: Blueprints are stored as RouterNode for consistency with FastAPI.
        """
        for generic_node in self.filter.blueprints:
            node = self.node_mapper.map_routing_config(
                generic_node,
                self.project_hash,
                self.core_graph.project_path
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_endpoints(self) -> None:
        """Map GenericNode endpoints to EndpointNode.
        
        Example: @app.route('/users') def get_users() -> EndpointNode
        """
        for func_node, decorator_node in self.filter.endpoints:
            node = self.node_mapper.map_request_handler(
                func_node,
                decorator_node,
                self.project_hash,
                self.core_graph.project_path
            )
            self.nodes.append(node)
            self.generic_to_domain_id[func_node.id] = node.id

    def _map_services(self) -> None:
        """Map GenericNode services to ServiceClassNode."""
        for generic_node in self.filter.services:
            # Get method names from children
            children = self.core_graph.get_children(generic_node.id)
            method_names = [c.name for c in children if c.node_type == GenericNodeType.METHOD]

            # Get base classes from metadata
            base_classes = generic_node.metadata.get("base_classes", [])
            primary_base_class = base_classes[0] if base_classes else None

            unique_id = self._get_unique_id_from_generic(generic_node.id)
            node = ServiceClassNode(
                id=f"service.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=generic_node.name,
                path=str(generic_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"Service class: {generic_node.name}",
                class_name=generic_node.name,
                module_path=str(generic_node.file_path.relative_to(self.core_graph.project_path)),
                methods=method_names,
                start_line=generic_node.start_line,
                parent_class=primary_base_class,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_methods(self) -> None:
        """Map GenericNode methods to MethodNode."""
        for generic_node in self.filter.methods:
            # Get parent service
            parent_generic = self.core_graph.get_parent(generic_node.id)
            parent_name = parent_generic.name if parent_generic else "Unknown"

            # Determine if method is async, private, or helper
            is_async = "async def" in (generic_node.source_code or "")
            is_private = generic_node.name.startswith("_")
            is_helper = generic_node.name.startswith("_") and not generic_node.name.startswith("__")

            unique_id = self._get_unique_id_from_generic(generic_node.id)
            node = MethodNode(
                id=f"method.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=generic_node.name,
                path=str(generic_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"Method {generic_node.name} in {parent_name}",
                is_async=is_async,
                is_private=is_private,
                is_helper=is_helper,
                start_line=generic_node.start_line,
                end_line=generic_node.end_line,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_functions(self) -> None:
        """Map GenericNode functions to FunctionNode."""
        for generic_node in self.filter.functions:
            # Skip if already mapped as an endpoint (endpoints are also functions)
            if generic_node.id in self.generic_to_domain_id:
                continue

            node = FunctionNode.from_generic_node(
                generic_node=generic_node,
                project_path=self.core_graph.project_path,
                project_hash=self.project_hash,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

            # Update function_lookup with actual node ID
            path_norm = node.path.replace("\\", "/")
            self.function_lookup[(path_norm, node.function_name, node.start_line)] = node.id

    def _map_entry_points(self) -> None:
        """Map GenericNode entry points to EntryPointNode."""
        for generic_node in self.filter.entry_points:
            unique_id = self._get_unique_id_from_generic(generic_node.id)
            node = EntryPointNode(
                id=f"entry_point.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=generic_node.name,
                path=str(generic_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"Entry point: {generic_node.name}",
                function_name=generic_node.name,
                start_line=generic_node.start_line,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    # ============================================================================
    # Phase 3: Edge Mapping Methods
    # ============================================================================

    def _map_edges(self) -> None:
        """Map GenericEdges to domain-specific GraphEdges."""
        # Discover blueprint registration edges (app → blueprint)
        if self.binder and self.query_engine:
            from engine.frameworks.flask.discovery import FlaskEdgeDiscoverer
            parse_cache = ParseCache(self.core_graph.project_path, self.query_engine.parser)
            discoverer = FlaskEdgeDiscoverer(
                self.filter,
                self.binder,
                self.query_engine,
                parse_cache,
                self.project_hash,
                self.generic_to_domain_id,
            )
            self.edges.extend(discoverer.discover())
        
        # Map other edge types
        self._map_has_endpoint_edges()
        self._map_calls_edges()
        self._map_contains_edges()
        self._map_calls_function_edges()
        self._map_initializes_edges()
        self._map_inheritance_edges()

    def _map_has_endpoint_edges(self) -> None:
        """Map blueprint → endpoint & application → endpoint 'has_endpoint' edges."""
        for func_node, decorator_node in self.filter.endpoints:
            decorator_parts = decorator_node.name.split(".")
            if len(decorator_parts) < 2 or func_node.id not in self.generic_to_domain_id:
                continue

            var_name = decorator_parts[0]
            endpoint_id = self.generic_to_domain_id[func_node.id]

            # Try to find blueprint in same file
            blueprint_generic = next(
                (bp for bp in self.filter.blueprints if bp.name == var_name and bp.file_path == func_node.file_path), 
                None
            )
            if blueprint_generic:
                blueprint_id = self.generic_to_domain_id.get(blueprint_generic.id)
                if blueprint_id:
                    self.edges.append(
                        self._create_edge(blueprint_id, endpoint_id, EdgeRelation.has_endpoint, "has_endpoint")
                    )
                continue

            # Try to find application in same file
            app_generic = next(
                (a for a in self.filter.applications if a.name == var_name and a.file_path == func_node.file_path), 
                None
            )
            if app_generic:
                app_id = self.generic_to_domain_id.get(app_generic.id)
                if app_id:
                    self.edges.append(
                        self._create_edge(app_id, endpoint_id, EdgeRelation.has_endpoint, "has_endpoint")
                    )

    def _map_calls_edges(self) -> None:
        """Map endpoint → service & service → service 'calls' edges."""
        if not self.binder or not self.query_engine:
            return

        # Use parser from query_engine
        parser = self.query_engine.parser

        # Track which services each node calls (avoid duplicates)
        calls_map = {}  # {source_domain_id: {target_service_ids}}

        # Build service lookup
        service_nodes = {
            self.generic_to_domain_id.get(s.id): s 
            for s in self.filter.services 
            if self.generic_to_domain_id.get(s.id)
        }

        # 1. Extract endpoint → service edges
        for func_node, decorator_node in self.filter.endpoints:
            endpoint_id = self.generic_to_domain_id.get(func_node.id)
            if not endpoint_id:
                continue

            tree = parser.parse_file(func_node.file_path)
            if not tree:
                continue

            service_ids = self._find_service_calls_in_function(tree, func_node, service_nodes, parser)
            if service_ids:
                calls_map[endpoint_id] = service_ids

        # 2. Extract service → service edges (analyze service methods)
        for service_generic in self.filter.services:
            service_id = self.generic_to_domain_id.get(service_generic.id)
            if not service_id:
                continue

            # Parse the service file
            tree = parser.parse_file(service_generic.file_path)
            if not tree:
                continue

            # Find all methods in this service
            service_children = self.core_graph.get_children(service_generic.id)
            methods = [c for c in service_children if c.node_type == GenericNodeType.METHOD]

            # Aggregate service calls across all methods in this service
            aggregated_calls = set()
            for method_generic in methods:
                service_ids = self._find_service_calls_in_function(tree, method_generic, service_nodes, parser)
                aggregated_calls.update(service_ids)

            if aggregated_calls:
                if service_id not in calls_map:
                    calls_map[service_id] = set()
                calls_map[service_id].update(aggregated_calls)

        # Create edges from the calls map
        for source_id, target_ids in calls_map.items():
            for target_id in target_ids:
                # Don't create self-loops
                if source_id == target_id:
                    continue

                self.edges.append(self._create_edge(source_id, target_id, EdgeRelation.calls, "calls"))

    def _find_service_calls_in_function(
        self, tree, func_generic_node, service_nodes: Dict[str, GenericNode], parser
    ) -> set:
        """Find all service calls within a function using Binder."""
        service_ids = set()

        # Find the function definition node in the tree
        func_name = func_generic_node.name
        func_line = func_generic_node.start_line

        # Traverse tree to find the function node at the right line
        def find_function_node(node: TSNode, target_line: int) -> Optional[TSNode]:
            if node.type in ["function_definition", "decorated_definition"]:
                if node.start_point[0] + 1 == target_line or (
                    node.type == "decorated_definition"
                    and any(child.start_point[0] + 1 == target_line for child in node.children)
                ):
                    if node.type == "decorated_definition":
                        # Get the actual function_definition
                        for child in node.children:
                            if child.type == "function_definition":
                                return child
                    return node

            for child in node.children:
                result = find_function_node(child, target_line)
                if result:
                    return result
            return None

        func_node = find_function_node(tree.root_node, func_line)
        if not func_node:
            return service_ids

        # Find body node
        body_node = func_node.child_by_field_name("body")
        if not body_node:
            return service_ids

        # Find all call nodes in the body
        def find_calls(node: TSNode):
            calls = []
            if node.type == ExpressionType.CALL:
                calls.append(node)
            for child in node.children:
                calls.extend(find_calls(child))
            return calls

        call_nodes = find_calls(body_node)

        # Analyze each call to see if it's a service call
        for call_node in call_nodes:
            func_attr = call_node.child_by_field_name("function")
            if not func_attr or func_attr.type != ExpressionType.ATTRIBUTE:
                # Also check for direct instantiation: ServiceClass()
                if func_attr and func_attr.type == ExpressionType.IDENTIFIER:
                    class_name = func_attr.text.decode("utf-8")
                    # Check if this is a service class instantiation
                    for service_id, service_generic in service_nodes.items():
                        if service_generic.name == class_name:
                            service_ids.add(service_id)
                            break
                continue

            # This is an attribute call like obj.method()
            service_var_node = func_attr.child_by_field_name("object")
            if not service_var_node:
                continue

            # Use binder to resolve
            bound = None
            try:
                if service_var_node.type == ExpressionType.IDENTIFIER:
                    bound = self.binder.resolve_identifier(func_generic_node.file_path, service_var_node)
                elif service_var_node.type == ExpressionType.ATTRIBUTE:
                    bound = self.binder.resolve_attribute_access(func_generic_node.file_path, service_var_node)
            except Exception:
                continue

            if not bound:
                continue

            if isinstance(bound, ServiceClassNode):
                for service_id, service_generic in service_nodes.items():
                    if service_generic.name == bound.class_name:
                        service_ids.add(service_id)
                        break
            else:
                class_name = None
                if hasattr(bound, "class_name"):
                    class_name = bound.class_name
                elif hasattr(bound, "name"):
                    class_name = bound.name
                elif hasattr(bound, "type_name"):
                    class_name = bound.type_name

                if class_name:
                    for service_id, service_generic in service_nodes.items():
                        if service_generic.name == class_name:
                            service_ids.add(service_id)
                            break

        return service_ids

    def _map_contains_edges(self) -> None:
        """Map service → method 'contains' edges."""
        for service_generic in self.filter.services:
            service_id = self.generic_to_domain_id.get(service_generic.id)
            if not service_id:
                continue

            children = self.core_graph.get_children(service_generic.id)
            for child in children:
                if child.node_type == GenericNodeType.METHOD:
                    method_id = self.generic_to_domain_id.get(child.id)
                    if method_id:
                        self.edges.append(
                            self._create_edge(service_id, method_id, EdgeRelation.contains, "contains")
                        )

    def _map_calls_function_edges(self) -> None:
        """Map function → function 'calls_function' edges."""
        if self.call_graph_result:
            # Skip - using comprehensive call graph edges instead
            return

        calls_edges = self.core_graph.get_edges_by_type(GenericEdgeType.CALLS)

        # Build set of function IDs for fast lookup
        function_ids = {f.id for f in self.filter.functions}

        for generic_edge in calls_edges:
            source_node = self.core_graph.get_node(generic_edge.source_id)
            target_node = self.core_graph.get_node(generic_edge.target_id)

            if not source_node or not target_node:
                continue

            # Only map if BOTH are functions (not methods, not endpoints)
            if source_node.id in function_ids and target_node.id in function_ids:
                source_id = self.generic_to_domain_id.get(generic_edge.source_id)
                target_id = self.generic_to_domain_id.get(generic_edge.target_id)

                if source_id and target_id:
                    self.edges.append(
                        self._create_edge(source_id, target_id, EdgeRelation.calls_function, "calls_function")
                    )

    def _map_initializes_edges(self) -> None:
        """Map entry point → service 'initializes' edges."""
        # Look for entry points and check if they instantiate services
        for entry_point in self.filter.entry_points:
            # Check source code for service instantiation patterns
            if entry_point.source_code:
                for service in self.filter.services:
                    # Simple pattern: ServiceName() appears in entry point code
                    if f"{service.name}(" in entry_point.source_code:
                        entry_point_id = self.generic_to_domain_id.get(entry_point.id)
                        service_id = self.generic_to_domain_id.get(service.id)

                        if entry_point_id and service_id:
                            self.edges.append(
                                self._create_edge(entry_point_id, service_id, EdgeRelation.initializes, "initializes")
                            )

    def _map_inheritance_edges(self) -> None:
        """Map class inheritance edges from CoreGraph."""
        inheritance_edges = self.core_graph.get_edges_by_type(GenericEdgeType.INHERITS)

        for generic_edge in inheritance_edges:
            child_id = self.generic_to_domain_id.get(generic_edge.source_id)
            parent_id = self.generic_to_domain_id.get(generic_edge.target_id)

            if child_id and parent_id:
                self.edges.append(
                    self._create_edge(child_id, parent_id, EdgeRelation.inherits, "inherits")
                )

                # Update parent's inheritance_children list
                for node in self.nodes:
                    if node.id == parent_id and isinstance(node, ServiceClassNode):
                        if child_id not in node.inheritance_children:
                            node.inheritance_children.append(child_id)
    
    # ============================================================================
    # Advanced Pattern Mapping (Phase 5)
    # ============================================================================
    
    def _map_methodview_endpoints(self) -> None:
        """Map MethodView HTTP methods to EndpointNode.
        
        MethodView classes have methods like get(), post() that are HTTP endpoints.
        """
        for class_node, http_methods in self.filter.methodview_classes:
            for method_info in http_methods:
                method_node = method_info["node"]
                http_verb = method_info["http_verb"]
                
                # Create EndpointNode for this HTTP method
                unique_id = self._get_unique_id_from_generic(method_node.id)
                endpoint_node = EndpointNode(
                    id=f"endpoint.{self.project_hash}.{unique_id}",
                    project_hash=self.project_hash,
                    name=method_node.name,
                    path=str(method_node.file_path.relative_to(self.core_graph.project_path)),
                    summary=f"MethodView endpoint: {class_node.name}.{method_node.name}",
                    http_path=f"/{class_node.name.lower()}",  # Placeholder - actual path from add_url_rule
                    http_verb=http_verb,
                    summary_one_liner=f"{http_verb} endpoint in MethodView {class_node.name}",
                    framework="flask",
                    start_line=method_node.start_line,
                    end_line=method_node.end_line,
                )
                
                self.nodes.append(endpoint_node)
                self.generic_to_domain_id[method_node.id] = endpoint_node.id
    
    def _map_extensions(self) -> None:
        """Map Flask extension instantiations to ServiceClassNode.
        
        Extensions like SQLAlchemy, Migrate are treated as special services.
        """
        for extension_node in self.filter.extensions:
            # Skip if already mapped
            if extension_node.id in self.generic_to_domain_id:
                continue
            
            unique_id = self._get_unique_id_from_generic(extension_node.id)
            service_node = ServiceClassNode(
                id=f"service.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=extension_node.name,
                path=str(extension_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"Flask extension: {extension_node.name}",
                class_name=extension_node.name,
                module_path=str(extension_node.file_path.relative_to(self.core_graph.project_path)),
                methods=[],  # Extensions don't have visible methods
                start_line=extension_node.start_line,
            )
            
            self.nodes.append(service_node)
            self.generic_to_domain_id[extension_node.id] = service_node.id
    
    def _map_extension_initialization_edges(self) -> None:
        """Map extension → app 'initializes' edges.
        
        Pattern: db.init_app(app) creates edge from db to app
        """
        for init_node, init_data in self.filter.extension_initializations:
            extension_var = init_data.get("extension")
            app_var = init_data.get("app_var")
            
            if not extension_var or not app_var:
                continue
            
            # Find extension node in same file
            extension_generic = next(
                (ext for ext in self.filter.extensions 
                 if ext.name == extension_var and ext.file_path == init_node.file_path),
                None
            )
            
            # Find app node in same file
            app_generic = next(
                (app for app in self.filter.applications 
                 if app.name == app_var and app.file_path == init_node.file_path),
                None
            )
            
            if extension_generic and app_generic:
                ext_id = self.generic_to_domain_id.get(extension_generic.id)
                app_id = self.generic_to_domain_id.get(app_generic.id)
                
                if ext_id and app_id:
                    self.edges.append(
                        self._create_edge(ext_id, app_id, EdgeRelation.initializes, "initializes")
                    )
    
    def _map_context_dependency_edges(self) -> None:
        """Map Flask context dependencies.
        
        Creates depends_on edges for Flask context usage (g, request, session).
        Note: Context objects are pseudo-nodes (not real nodes), so we track
        usage in endpoint/function metadata rather than creating edges.
        
        For now, this is tracked in filter.context_dependencies for future use.
        """
        # This is informational for now - could be expanded to create
        # special context edges or add to node metadata
        pass
    
    def _map_methodview_endpoints(self) -> None:
        """Map MethodView HTTP methods to EndpointNode.
        
        MethodView classes have methods like get(), post() that are HTTP endpoints.
        """
        for class_node, http_methods in self.filter.methodview_classes:
            for method_info in http_methods:
                method_node = method_info["node"]
                http_verb = method_info["http_verb"]
                
                # Create EndpointNode for this HTTP method
                unique_id = self._get_unique_id_from_generic(method_node.id)
                endpoint_node = EndpointNode(
                    id=f"endpoint.{self.project_hash}.{unique_id}",
                    project_hash=self.project_hash,
                    name=method_node.name,
                    path=str(method_node.file_path.relative_to(self.core_graph.project_path)),
                    summary=f"MethodView endpoint: {class_node.name}.{method_node.name}",
                    http_path=f"/{class_node.name.lower()}",  # Placeholder
                    http_verb=http_verb,
                    summary_one_liner=f"{http_verb} endpoint in MethodView {class_node.name}",
                    framework="flask",
                    start_line=method_node.start_line,
                    end_line=method_node.end_line,
                )
                
                self.nodes.append(endpoint_node)
                self.generic_to_domain_id[method_node.id] = endpoint_node.id
    
    def _map_extensions(self) -> None:
        """Map Flask extension instantiations to ServiceClassNode.
        
        Extensions like SQLAlchemy, Migrate are treated as special services.
        """
        for extension_node in self.filter.extensions:
            # Skip if already mapped
            if extension_node.id in self.generic_to_domain_id:
                continue
            
            unique_id = self._get_unique_id_from_generic(extension_node.id)
            service_node = ServiceClassNode(
                id=f"service.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=extension_node.name,
                path=str(extension_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"Flask extension: {extension_node.name}",
                class_name=extension_node.name,
                module_path=str(extension_node.file_path.relative_to(self.core_graph.project_path)),
                methods=[],
                start_line=extension_node.start_line,
            )
            
            self.nodes.append(service_node)
            self.generic_to_domain_id[extension_node.id] = service_node.id
    
    def _map_extension_initialization_edges(self) -> None:
        """Map extension → app 'initializes' edges.
        
        Pattern: db.init_app(app) creates edge from extension to app.
        """
        for init_node, init_data in self.filter.extension_initializations:
            extension_var = init_data.get("extension")
            app_var = init_data.get("app_var")
            
            if not extension_var or not app_var:
                continue
            
            # Find extension node in same file
            extension_generic = next(
                (ext for ext in self.filter.extensions 
                 if ext.name == extension_var and ext.file_path == init_node.file_path),
                None
            )
            
            # Find app node in same file
            app_generic = next(
                (app for app in self.filter.applications 
                 if app.name == app_var and app.file_path == init_node.file_path),
                None
            )
            
            if extension_generic and app_generic:
                ext_id = self.generic_to_domain_id.get(extension_generic.id)
                app_id = self.generic_to_domain_id.get(app_generic.id)
                
                if ext_id and app_id:
                    self.edges.append(
                        self._create_edge(ext_id, app_id, EdgeRelation.initializes, "initializes")
                    )
    
