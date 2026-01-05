from pathlib import Path
from typing import List, Dict, Optional, Tuple
import re

from engine.models import CoreGraph, GenericNode, GenericEdge, GenericNodeType, GenericEdgeType
from engine.models import (
    ApplicationNode,
    RouterNode,
    EndpointNode,
    ServiceClassNode,
    MethodNode,
    FunctionNode,
    EntryPointNode,
)
from engine.models import ExpressionType, GraphNode, GraphEdge, EdgeRelation
from engine.frameworks.fastapi.filter import FastAPIFilter
from engine.graph.call_graph import CallGraphResult
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser.query_engine import QueryEngine
from engine.parser.parse_cache import ParseCache
from engine.frameworks.fastapi.discovery import FastAPIEdgeDiscoverer
from engine.frameworks.fastapi.dependency_resolver import FastAPIDependencyResolver
from engine.frameworks.fastapi.node_mapper import FastAPINodeMapper
from engine.frameworks.base import DomainMapper, NodeMapper
from tree_sitter import Node as TSNode


class FastAPIDomainMapper(DomainMapper):
    """
    Maps GenericNodes from CoreGraph to FastAPI-specific domain models.

    Takes filtered GenericNodes and creates GraphNodes (ApplicationNode, RouterNode, etc.)
    and GraphEdges (includes, has_endpoint, calls, contains, etc.).
    """

    def __init__(
        self,
        core_graph: CoreGraph,
        fastapi_filter: FastAPIFilter,
        project_hash: str,
        call_graph_result: Optional[CallGraphResult] = None,
        binder: Optional[SymbolResolver] = None,
        query_engine: Optional[QueryEngine] = None,
    ):
        self.core_graph = core_graph
        self.filter = fastapi_filter
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
        self.node_mapper: NodeMapper = FastAPINodeMapper(project_hash, core_graph.project_path)

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
        """Map filtered GenericNodes to domain models."""
        # Map nodes in dependency order
        self._map_applications()
        self._map_routers()

        # Index apps and routers in SymbolIndex BEFORE mapping edges
        if self.binder:
            app_nodes = [n for n in self.nodes if isinstance(n, ApplicationNode)]
            router_nodes = [n for n in self.nodes if isinstance(n, RouterNode)]
            self.binder.symbol_index.index_applications(app_nodes)
            self.binder.symbol_index.index_routers(router_nodes)

        self._map_endpoints()

        # Build function lookup from call graph for dependency resolution
        # Don't add nodes yet - let _map_functions() handle that to avoid duplicates
        if self.call_graph_result:
            for generic_func in self.call_graph_result.function_nodes:
                rel_path = str(generic_func.file_path.relative_to(self.core_graph.project_path))
                path_norm = rel_path.replace("\\", "/")
                # Create temporary ID for lookup (will be created properly by _map_functions)
                temp_id = f"function.{self.project_hash}.{generic_func.id.split(':')[-1]}"
                self.function_lookup[(path_norm, generic_func.name, generic_func.start_line)] = temp_id

        self._map_services()
        self._map_methods()
        self._map_functions()  # Map functions FIRST so dependency resolver can find them
        self._map_entry_points()
        self._map_dependencies()  # Map dependencies AFTER functions so IDs match

        # Map edges
        self._map_edges()

        # Add call graph edges if available (but only edges where both nodes exist AND are domain-appropriate)
        if self.call_graph_result:
            # Build a set of all node IDs we have
            all_node_ids = {node.id for node in self.nodes}

            # Build sets of specific node types for filtering
            entry_point_ids = {
                self.generic_to_domain_id.get(ep.id)
                for ep in self.filter.entry_points
                if self.generic_to_domain_id.get(ep.id)
            }
            router_ids = {
                self.generic_to_domain_id.get(r.id) for r in self.filter.routers if self.generic_to_domain_id.get(r.id)
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

            # Filter call graph edges to only include edges where both src and dst exist
            # AND the edge makes sense from a FastAPI domain perspective
            valid_call_edges = []

            for edge in self.call_graph_result.call_edges:
                # Check if both nodes exist
                if edge.src_id not in all_node_ids or edge.dst_id not in all_node_ids:
                    continue

                # Domain-specific filtering: Skip edges that don't make sense
                if (
                    edge.src_id in entry_point_ids
                    or edge.src_id in router_ids
                    or edge.src_id in application_ids
                    or edge.src_id in endpoint_ids
                ):
                    continue
                if edge.dst_id in router_ids or edge.dst_id in application_ids or edge.dst_id in endpoint_ids:
                    continue

                valid_call_edges.append(edge)

            self.edges.extend(valid_call_edges)

        return self.nodes, self.edges

    def _get_unique_id_from_generic(self, generic_id: str) -> str:
        """Extract a unique identifier from a generic node ID."""
        # Generic IDs are like "project_hash:node_type:hash123"
        parts = generic_id.split(":")
        if len(parts) >= 3:
            return parts[2]  # Return the hash portion
        # Fallback: use the full ID if format is unexpected
        return generic_id.replace(":", "_")

    def _map_applications(self) -> None:
        """Map GenericNode applications to ApplicationNode"""
        for generic_node in self.filter.applications:
            node = self.node_mapper.map_entry_point(generic_node, self.project_hash, self.core_graph.project_path)
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_routers(self) -> None:
        """Map GenericNode routers to RouterNode"""
        for generic_node in self.filter.routers:
            node = self.node_mapper.map_routing_config(generic_node, self.project_hash, self.core_graph.project_path)
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_endpoints(self) -> None:
        """Map GenericNode endpoints to EndpointNode"""
        for func_node, decorator_node in self.filter.endpoints:
            node = self.node_mapper.map_request_handler(
                func_node, decorator_node, self.project_hash, self.core_graph.project_path
            )
            self.nodes.append(node)
            self.generic_to_domain_id[func_node.id] = node.id

    def _map_dependencies(self) -> None:
        """Map FastAPI dependencies to depends_on edges."""
        if not self.binder or not self.query_engine:
            return

        resolver = FastAPIDependencyResolver(self.binder, self.query_engine, self.project_hash)
        python_files = {dep[0].file_path for dep in self.filter.dependencies}
        self.binder.symbol_index.infer_and_index_return_types(list(python_files))

        dependency_edges: List[GraphEdge] = []
        provider_ids: set = set()

        for generic_node, depends_node, scope in self.filter.dependencies:
            source_id = self.generic_to_domain_id.get(generic_node.id)
            if not source_id:
                continue

            file_path = generic_node.file_path
            if not file_path.is_absolute():
                file_path = self.core_graph.project_path / file_path

            provider = resolver.extract_provider_from_node(depends_node, file_path)
            if not provider:
                continue

            provider_path = provider.path
            if Path(provider_path).is_absolute():
                provider_path = str(Path(provider_path).relative_to(self.core_graph.project_path))
            provider_path_norm = provider_path.replace("\\", "/")

            provider_id = self._find_function_node_id(provider_path_norm, provider.name, provider.start_line)
            if not provider_id:
                self.nodes.append(provider)
                self.function_lookup[(provider_path_norm, provider.name, provider.start_line)] = provider.id
                provider_id = provider.id
            else:
                pass

            provider_ids.add(provider_id)
            dependency_edges.append(self._create_edge(source_id, provider_id, EdgeRelation.depends_on, "depends_on"))

            prev_id = provider_id
            for nested in resolver.resolve_dependency_chain(provider, depth=0, max_depth=10):
                nested_path = nested.path
                if Path(nested_path).is_absolute():
                    nested_path = str(Path(nested_path).relative_to(self.core_graph.project_path))
                nested_path_norm = nested_path.replace("\\", "/")

                nested_id = self._find_function_node_id(nested_path_norm, nested.name, nested.start_line)
                if not nested_id:
                    self.nodes.append(nested)
                    self.function_lookup[(nested_path_norm, nested.name, nested.start_line)] = nested.id
                    nested_id = nested.id
                else:
                    pass
                provider_ids.add(nested_id)
                dependency_edges.append(self._create_edge(prev_id, nested_id, EdgeRelation.depends_on, "depends_on"))
                prev_id = nested_id

        self.edges.extend(dependency_edges)

    def _find_function_node_id(self, path: str, name: str, start_line: int) -> Optional[str]:
        """Find FunctionNode ID by matching path, name, and line."""
        path_norm = path.replace("\\", "/")
        if (path_norm, name, start_line) in self.function_lookup:
            return self.function_lookup[(path_norm, name, start_line)]

        for node in self.nodes:
            if isinstance(node, FunctionNode):
                if (
                    node.path.replace("\\", "/") == path_norm
                    and node.function_name == name
                    and node.start_line == start_line
                ):
                    return node.id

        return None

    def _map_services(self) -> None:
        """Map GenericNode services to ServiceClassNode"""
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
                parent_class=primary_base_class,  # Store parent class name
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_inheritance(self) -> None:
        """
        Map inheritance relationships between ServiceClassNodes.
        Creates 'inherits' edges from child class to parent class.
        """
        # Create a lookup for service classes by name
        service_lookup = {node.class_name: node for node in self.nodes if isinstance(node, ServiceClassNode)}

        inheritance_edges: List[GraphEdge] = []

        for node in self.nodes:
            if not isinstance(node, ServiceClassNode) or not node.parent_class:
                continue

            # Try to find parent class node
            parent_node = service_lookup.get(node.parent_class)

            # If not found by simple name match, try to resolve using binder (if available)
            if not parent_node and self.binder:
                # Simple name matching covers most intra-project cases
                # Deeper resolution using Binder could be added here if needed
                pass

            if parent_node:
                # Create inheritance edge
                edge = self._create_edge(node.id, parent_node.id, EdgeRelation.inherits, "inherits")
                inheritance_edges.append(edge)

                # Update parent's children list
                if node.id not in parent_node.inheritance_children:
                    parent_node.inheritance_children.append(node.id)

        self.edges.extend(inheritance_edges)

    def _map_methods(self) -> None:
        """Map GenericNode methods to MethodNode"""
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
        """Map GenericNode functions to FunctionNode"""
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
        """Map GenericNode entry points to EntryPointNode"""
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

    def _map_edges(self) -> None:
        """Map GenericEdges to domain-specific GraphEdges"""
        if self.binder and self.query_engine:
            parse_cache = ParseCache(self.core_graph.project_path, self.query_engine.parser)
            discoverer = FastAPIEdgeDiscoverer(
                self.filter,
                self.binder,
                self.query_engine,
                parse_cache,
                self.project_hash,
                self.generic_to_domain_id,
            )
            self.edges.extend(discoverer.discover())

        self._map_has_endpoint_edges()
        self._map_calls_edges()  # endpoint → service, service → service
        self._map_contains_edges()
        self._map_calls_function_edges()
        self._map_initializes_edges()
        self._map_inheritance_edges()  # child class → parent class

    def _map_has_endpoint_edges(self) -> None:
        """Map router → endpoint & application → endpoint "has_endpoint" edges."""
        for func_node, decorator_node in self.filter.endpoints:
            decorator_parts = decorator_node.name.split(".")
            if len(decorator_parts) < 2 or func_node.id not in self.generic_to_domain_id:
                continue

            var_name = decorator_parts[0]
            endpoint_id = self.generic_to_domain_id[func_node.id]

            # Try to find router in same file
            router_generic = next(
                (r for r in self.filter.routers if r.name == var_name and r.file_path == func_node.file_path), None
            )
            if router_generic:
                router_id = self.generic_to_domain_id.get(router_generic.id)
                if router_id:
                    self.edges.append(
                        self._create_edge(router_id, endpoint_id, EdgeRelation.has_endpoint, "has_endpoint")
                    )
                continue

            # Try to find application in same file
            app_generic = next(
                (a for a in self.filter.applications if a.name == var_name and a.file_path == func_node.file_path), None
            )
            if app_generic:
                app_id = self.generic_to_domain_id.get(app_generic.id)
                if app_id:
                    self.edges.append(self._create_edge(app_id, endpoint_id, EdgeRelation.has_endpoint, "has_endpoint"))

    def _map_calls_edges(self) -> None:
        """Map endpoint → service & service → service."""
        if not self.binder or not self.query_engine:
            return

        # Use parser from query_engine instead of creating new
        parser = self.query_engine.parser

        # Track which services each node calls (avoid duplicates)
        calls_map = {}  # {source_domain_id: {target_service_ids}}

        # Build service lookup
        service_nodes = {
            self.generic_to_domain_id.get(s.id): s for s in self.filter.services if self.generic_to_domain_id.get(s.id)
        }

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
        """Map service → method "contains" edges."""
        for service_generic in self.filter.services:
            service_id = self.generic_to_domain_id.get(service_generic.id)
            if not service_id:
                continue

            children = self.core_graph.get_children(service_generic.id)
            for child in children:
                if child.node_type == GenericNodeType.METHOD:
                    method_id = self.generic_to_domain_id.get(child.id)
                    if method_id:
                        self.edges.append(self._create_edge(service_id, method_id, EdgeRelation.contains, "contains"))

    def _map_calls_function_edges(self) -> None:
        """Map function → function "calls_function" edges."""
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
        """Map entry point → service "initializes" edges."""
        # For now, create a simple implementation
        # In full implementation, would need to detect service instantiation patterns
        # from the CoreGraph

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
        """Map class inheritance edges from CoreGraph"""
        inheritance_edges = self.core_graph.get_edges_by_type(GenericEdgeType.INHERITS)

        for generic_edge in inheritance_edges:
            child_id = self.generic_to_domain_id.get(generic_edge.source_id)
            parent_id = self.generic_to_domain_id.get(generic_edge.target_id)

            if child_id and parent_id:
                self.edges.append(self._create_edge(child_id, parent_id, EdgeRelation.inherits, "inherits"))

                # Update parent's inheritance_children list
                for node in self.nodes:
                    if node.id == parent_id and isinstance(node, ServiceClassNode):
                        if child_id not in node.inheritance_children:
                            node.inheritance_children.append(child_id)
