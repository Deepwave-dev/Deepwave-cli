from pathlib import Path
from typing import List, Dict, Optional, Tuple
from loguru import logger
import re

from deepwave_engine.models import CoreGraph, GenericNode, GenericEdge, GenericNodeType, GenericEdgeType
from deepwave_engine.models import (
    ApplicationNode,
    RouterNode,
    EndpointNode,
    ServiceClassNode,
    MethodNode,
    FunctionNode,
    EntryPointNode,
)
from deepwave_engine.models import GraphNode, GraphEdge, EdgeRelation
from deepwave_engine.frameworks.fastapi.filter import FastAPIFilter
from deepwave_engine.graph.call_graph import CallGraphResult
from deepwave_engine.binder.binder_treesitter import BinderTreeSitter
from deepwave_engine.parser.query_engine import QueryEngine
from deepwave_engine.parser.parse_cache import ParseCache
from deepwave_engine.frameworks.fastapi.discovery import IncludesEdgeDiscoverer
from deepwave_engine.frameworks.fastapi.dependency_resolver import DependencyResolver
from deepwave_engine.frameworks.base import DomainMapper
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
        binder: Optional[BinderTreeSitter] = None,
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

    def map(self) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Map filtered GenericNodes to domain models."""
        # Map nodes in dependency order
        self._map_applications()
        self._map_routers()

        # Index apps and routers in SymbolIndex BEFORE mapping edges
        # This is needed for IncludesEdgeDiscoverer to resolve routers/apps via Binder
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

        self._map_dependencies()
        self._map_services()
        self._map_methods()
        self._map_functions()  # This will create actual FunctionNodes
        self._map_entry_points()

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
            skipped_edges = 0
            domain_filtered = 0

            for edge in self.call_graph_result.call_edges:
                # Check if both nodes exist
                if edge.src_id not in all_node_ids or edge.dst_id not in all_node_ids:
                    skipped_edges += 1
                    continue

                # Domain-specific filtering: Skip edges that don't make sense
                if (
                    edge.src_id in entry_point_ids
                    or edge.src_id in router_ids
                    or edge.src_id in application_ids
                    or edge.src_id in endpoint_ids
                ):
                    domain_filtered += 1
                    continue
                if edge.dst_id in router_ids or edge.dst_id in application_ids or edge.dst_id in endpoint_ids:
                    domain_filtered += 1
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
            # Use generic node ID to ensure uniqueness
            unique_id = self._get_unique_id_from_generic(generic_node.id)
            node = ApplicationNode(
                id=f"app.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=generic_node.name,
                path=str(generic_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"FastAPI application: {generic_node.name}",
                app_var=generic_node.name,
                start_line=generic_node.start_line,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_routers(self) -> None:
        """Map GenericNode routers to RouterNode"""
        for generic_node in self.filter.routers:
            unique_id = self._get_unique_id_from_generic(generic_node.id)

            # Create descriptive name from file path + variable name (like old implementation)
            module_name = generic_node.file_path.stem  # e.g., "repositories" from "repositories.py"
            display_name = f"{module_name}.{generic_node.name}"  # e.g., "repositories.router"

            node = RouterNode(
                id=f"router.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=display_name,
                path=str(generic_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"API Router: {display_name}",
                router_var=generic_node.name,
                prefix="",  # TODO: Extract from source code
                start_line=generic_node.start_line,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[generic_node.id] = node.id

    def _map_endpoints(self) -> None:
        """Map GenericNode endpoints to EndpointNode"""
        from deepwave_engine.models import EnumMethod

        for func_node, decorator_node in self.filter.endpoints:
            # Extract HTTP method from decorator name (e.g., "router.get" -> "GET")
            decorator_parts = decorator_node.name.split(".")
            http_method_str = decorator_parts[1].upper() if len(decorator_parts) >= 2 else "GET"

            # Map to EnumMethod
            method_map = {
                "GET": EnumMethod.GET,
                "POST": EnumMethod.POST,
                "PUT": EnumMethod.PUT,
                "DELETE": EnumMethod.DELETE,
                "PATCH": EnumMethod.PATCH,
                "OPTIONS": EnumMethod.OPTIONS,
                "HEAD": EnumMethod.HEAD,
            }
            http_method = method_map.get(http_method_str, EnumMethod.GET)

            unique_id = self._get_unique_id_from_generic(func_node.id)
            node = EndpointNode(
                id=f"endpoint.{self.project_hash}.{unique_id}",
                project_hash=self.project_hash,
                name=func_node.name,
                path=str(func_node.file_path.relative_to(self.core_graph.project_path)),
                summary=f"Endpoint: {func_node.name}",
                method=http_method,
                start_line=func_node.start_line,
                end_line=func_node.end_line,
                code_chunk=func_node.source_code,
            )
            self.nodes.append(node)
            self.generic_to_domain_id[func_node.id] = node.id

    def _map_dependencies(self) -> None:
        """
        Map FastAPI dependencies to depends_on edges connecting endpoints to provider functions.

        This handles both function-level and router-level dependencies, and
        recursively resolves nested dependency chains.
        """
        if not self.binder or not self.query_engine:
            logger.warning("Binder or QueryEngine not available - skipping dependency mapping")
            return

        # Initialize dependency resolver
        resolver = DependencyResolver(self.binder, self.query_engine)

        # Infer return types for dependency resolution
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

            provider = self._extract_provider_from_depends_node(depends_node, file_path, resolver)
            if not provider:
                continue

            provider_id = self._find_function_node_id(provider.path, provider.name, provider.start_line)
            if not provider_id:
                logger.debug(f"Provider function {provider.name} not found, skipping")
                continue

            provider_ids.add(provider_id)
            dependency_edges.append(
                GraphEdge(
                    id=f"depends_on.{source_id}.{provider_id}",
                    src_id=source_id,
                    dst_id=provider_id,
                    relation=EdgeRelation.depends_on,
                    project_hash=self.project_hash,
                )
            )

            # Resolve nested dependencies
            prev_id = provider_id
            for nested in resolver.resolve_dependency_chain(provider, depth=0, max_depth=10):
                nested_id = self._find_function_node_id(nested.path, nested.name, nested.start_line)
                if not nested_id:
                    logger.debug(f"Nested provider {nested.name} not found, breaking chain")
                    break
                provider_ids.add(nested_id)
                dependency_edges.append(
                    GraphEdge(
                        id=f"depends_on.{prev_id}.{nested_id}",
                        src_id=prev_id,
                        dst_id=nested_id,
                        relation=EdgeRelation.depends_on,
                        project_hash=self.project_hash,
                    )
                )
                prev_id = nested_id

        self.edges.extend(dependency_edges)
        logger.info(f"Mapped {len(dependency_edges)} dependency edges to {len(provider_ids)} providers")

    def _find_function_node_id(self, path: str, name: str, start_line: int) -> Optional[str]:
        """Find FunctionNode ID by matching path, name, and line using optimized lookup."""
        path_norm = path.replace("\\", "/")

        # Fast O(1) lookup
        if (path_norm, name, start_line) in self.function_lookup:
            return self.function_lookup[(path_norm, name, start_line)]

        # Fallback: Check if it was added to nodes but missed in lookup (rare sync issue)
        for node in self.nodes:
            if isinstance(node, FunctionNode):
                if (
                    node.path.replace("\\", "/") == path_norm
                    and node.function_name == name
                    and node.start_line == start_line
                ):
                    return node.id

        return None

    def _extract_provider_from_depends_node(
        self, depends_node: TSNode, file_path: Path, resolver: DependencyResolver
    ) -> Optional[FunctionNode]:
        """Extract provider function from a Depends() Tree-sitter node."""
        args_node = depends_node.child_by_field_name("arguments")
        if not args_node:
            return None

        for child in args_node.children:
            if child.type in ["identifier", "attribute", "call"]:
                provider = resolver.resolve_provider_from_argument(child, file_path)
                if provider:
                    return provider
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
                # TODO: Implement deeper resolution using Binder if needed
                # For now, simple name matching covers most intra-project cases
                pass

            if parent_node:
                # Create inheritance edge
                edge = GraphEdge(
                    id=f"inherits.{node.id}.{parent_node.id}",
                    src_id=node.id,
                    dst_id=parent_node.id,
                    relation=EdgeRelation.inherits,
                    project_hash=self.project_hash,
                )
                inheritance_edges.append(edge)

                # Update parent's children list
                if node.id not in parent_node.inheritance_children:
                    parent_node.inheritance_children.append(node.id)

        self.edges.extend(inheritance_edges)
        if inheritance_edges:
            logger.info(f"Mapped {len(inheritance_edges)} inheritance edges")

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
        mapped_count = 0
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
            mapped_count += 1

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
        # Use AST-based discoverer for includes edges if binder and query_engine are available
        if self.binder and self.query_engine:
            parse_cache = ParseCache(self.core_graph.project_path, self.query_engine.parser)
            includes_discoverer = IncludesEdgeDiscoverer(
                fastapi_filter=self.filter,
                binder=self.binder,
                query_engine=self.query_engine,
                parse_cache=parse_cache,
                project_hash=self.project_hash,
                generic_to_domain_id=self.generic_to_domain_id,
            )
            discovered_edges = includes_discoverer.discover()
            self.edges.extend(discovered_edges)
        else:
            # Fallback to regex (backward compatibility)
            self._map_includes_edges()

        self._map_has_endpoint_edges()
        self._map_calls_edges()  # endpoint → service, service → service
        self._map_contains_edges()
        self._map_calls_function_edges()
        self._map_initializes_edges()
        self._map_inheritance_edges()  # child class → parent class

    def _map_includes_edges(self) -> None:
        """
        Map "includes" edges: app → router and router → router.

        Pattern: Find include_router() calls:
        - app.include_router(router)
        - parent_router.include_router(child_router)
        """
        # App → Router includes
        for app_node in self.filter.applications:
            app_id = self.generic_to_domain_id.get(app_node.id)
            if not app_id:
                continue

            try:
                with open(app_node.file_path, "r") as f:
                    file_content = f.read()
            except Exception as e:
                logger.warning(f"Could not read {app_node.file_path}: {e}")
                continue

            pattern = rf"{app_node.name}\.include_router\s*\(\s*([^,\)]+)"
            matches = re.findall(pattern, file_content)

            for match in matches:
                router_ref = match.strip()

                # Extract module and variable name
                # e.g., "architecture.router" -> module="architecture", var="router"
                if "." in router_ref:
                    module_part, var_part = router_ref.rsplit(".", 1)
                else:
                    module_part = None
                    var_part = router_ref

                matched = False
                for router_node in self.filter.routers:
                    router_id = self.generic_to_domain_id.get(router_node.id)
                    if not router_id:
                        continue

                    # Match by variable name AND optionally by module
                    router_module = router_node.file_path.stem
                    if router_node.name == var_part:
                        # Check if module matches too (if specified)
                        if module_part is None or router_module == module_part:
                            edge = GraphEdge(
                                id=f"includes.{app_id}.{router_id}",
                                src_id=app_id,
                                dst_id=router_id,
                                relation=EdgeRelation.includes,
                                project_hash=self.project_hash,
                            )
                            self.edges.append(edge)
                            matched = True
                            break

        # Router → Router includes
        for parent_router in self.filter.routers:
            parent_id = self.generic_to_domain_id.get(parent_router.id)
            if not parent_id:
                continue

            try:
                with open(parent_router.file_path, "r") as f:
                    file_content = f.read()
            except Exception as e:
                logger.warning(f"Could not read {parent_router.file_path}: {e}")
                continue

            pattern = rf"{parent_router.name}\.include_router\(([^,\)]+)"
            matches = re.findall(pattern, file_content)

            for match in matches:
                router_ref = match.strip()

                for child_router in self.filter.routers:
                    if child_router.id == parent_router.id:
                        continue  # Skip self-includes

                    child_id = self.generic_to_domain_id.get(child_router.id)
                    if not child_id:
                        continue

                    if router_ref == child_router.name or router_ref.endswith(f".{child_router.name}"):
                        edge = GraphEdge(
                            id=f"includes.{parent_id}.{child_id}",
                            src_id=parent_id,
                            dst_id=child_id,
                            relation=EdgeRelation.includes,
                            project_hash=self.project_hash,
                        )
                        self.edges.append(edge)
                        break

    def _map_has_endpoint_edges(self) -> None:
        """Map router → endpoint & application → endpoint "has_endpoint" edges."""
        router_endpoint_count = 0
        app_endpoint_count = 0

        for func_node, decorator_node in self.filter.endpoints:
            decorator_parts = decorator_node.name.split(".")
            if len(decorator_parts) < 2 or func_node.id not in self.generic_to_domain_id:
                continue

            var_name = decorator_parts[0]

            # Try to find router in same file
            router_generic = next(
                (r for r in self.filter.routers if r.name == var_name and r.file_path == func_node.file_path), None
            )
            if router_generic:
                router_id = self.generic_to_domain_id.get(router_generic.id)
                endpoint_id = self.generic_to_domain_id.get(func_node.id)
                if router_id and endpoint_id:
                    edge = GraphEdge(
                        id=f"has_endpoint.{router_id}.{endpoint_id}",
                        src_id=router_id,
                        dst_id=endpoint_id,
                        relation=EdgeRelation.has_endpoint,
                        project_hash=self.project_hash,
                    )
                    self.edges.append(edge)
                    router_endpoint_count += 1
                continue

            # Try to find application in same file
            app_generic = next(
                (a for a in self.filter.applications if a.name == var_name and a.file_path == func_node.file_path), None
            )
            if app_generic:
                if func_node.id not in self.generic_to_domain_id:
                    continue

                app_id = self.generic_to_domain_id.get(app_generic.id)
                endpoint_id = self.generic_to_domain_id.get(func_node.id)

                if app_id and endpoint_id:
                    edge = GraphEdge(
                        id=f"has_endpoint.{app_id}.{endpoint_id}",
                        src_id=app_id,
                        dst_id=endpoint_id,
                        relation=EdgeRelation.has_endpoint,
                        project_hash=self.project_hash,
                    )
                    self.edges.append(edge)
                    app_endpoint_count += 1
                continue

    def _map_calls_edges(self) -> None:
        """Map endpoint → service & service → service."""
        if not self.binder or not self.query_engine:
            logger.warning("Binder or QueryEngine not available - skipping comprehensive calls edges")
            return

        from deepwave_engine.parser import TreeSitterParser

        parser = TreeSitterParser("python")

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

                edge = GraphEdge(
                    id=f"calls.{source_id}.{target_id}",
                    src_id=source_id,
                    dst_id=target_id,
                    relation=EdgeRelation.calls,
                    project_hash=self.project_hash,
                )
                self.edges.append(edge)

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
            if node.type == "call":
                calls.append(node)
            for child in node.children:
                calls.extend(find_calls(child))
            return calls

        call_nodes = find_calls(body_node)

        # Analyze each call to see if it's a service call
        for call_node in call_nodes:
            func_attr = call_node.child_by_field_name("function")
            if not func_attr or func_attr.type != "attribute":
                # Also check for direct instantiation: ServiceClass()
                if func_attr and func_attr.type == "identifier":
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
                if service_var_node.type == "identifier":
                    bound = self.binder.bind_name("", func_generic_node.file_path, service_var_node)
                elif service_var_node.type == "attribute":
                    bound = self.binder.bind_attribute("", func_generic_node.file_path, service_var_node)
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
                        edge = GraphEdge(
                            id=f"contains.{service_id}.{method_id}",
                            src_id=service_id,
                            dst_id=method_id,
                            relation=EdgeRelation.contains,
                            project_hash=self.project_hash,
                        )
                        self.edges.append(edge)

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
                    edge = GraphEdge(
                        id=f"calls_function.{source_id}.{target_id}",
                        src_id=source_id,
                        dst_id=target_id,
                        relation=EdgeRelation.calls_function,
                        project_hash=self.project_hash,
                    )
                    self.edges.append(edge)

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
                            edge = GraphEdge(
                                id=f"initializes.{entry_point_id}.{service_id}",
                                src_id=entry_point_id,
                                dst_id=service_id,
                                relation=EdgeRelation.initializes,
                                project_hash=self.project_hash,
                            )
                            self.edges.append(edge)

    def _map_inheritance_edges(self) -> None:
        """Map class inheritance edges from CoreGraph"""
        # Get all inheritance edges from CoreGraph
        inheritance_edges = self.core_graph.get_edges_by_type(GenericEdgeType.INHERITS)

        inheritance_edge_count = 0
        for generic_edge in inheritance_edges:
            # Map generic IDs to domain IDs
            child_id = self.generic_to_domain_id.get(generic_edge.source_id)
            parent_id = self.generic_to_domain_id.get(generic_edge.target_id)

            if child_id and parent_id:
                # Create inheritance edge
                edge = GraphEdge(
                    id=f"inherits.{child_id}.{parent_id}",
                    src_id=child_id,
                    dst_id=parent_id,
                    relation=EdgeRelation.inherits,
                    project_hash=self.project_hash,
                )
                self.edges.append(edge)
                inheritance_edge_count += 1

                # Update parent's inheritance_children list
                for node in self.nodes:
                    if node.id == parent_id and isinstance(node, ServiceClassNode):
                        if child_id not in node.inheritance_children:
                            node.inheritance_children.append(child_id)

        if inheritance_edge_count > 0:
            logger.info(f"Mapped {inheritance_edge_count} inheritance edges")
