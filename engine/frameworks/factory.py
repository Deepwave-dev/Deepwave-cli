from pathlib import Path
from typing import Optional

from engine.frameworks.base import FrameworkFilter, DomainMapper, DependencyResolver, EdgeDiscoverer
from engine.frameworks.fastapi.filter import FastAPIFilter
from engine.frameworks.fastapi.mapper import FastAPIDomainMapper
from engine.frameworks.django.filter import DjangoFilter
from engine.frameworks.django.mapper import DjangoDomainMapper
from engine.models import CoreGraph
from engine.graph.call_graph import CallGraphResult
from engine.binder.symbol_resolver import SymbolResolver
from engine.binder.resolution_strategy import ResolutionStrategy
from engine.binder import ImportGraph, SymbolIndex
from engine.parser.query_engine import QueryEngine
from engine.parser.parse_cache import ParseCache


class FrameworkFactory:
    """Factory for creating framework-specific components."""

    @staticmethod
    def get_resolution_strategy(framework: str) -> ResolutionStrategy:
        """Get resolution strategy for the framework."""
        if framework == "django":
            # TODO: Implement DjangoResolutionStrategy when Django support is added
            # from engine.frameworks.django.resolution_strategy import DjangoResolutionStrategy
            # return DjangoResolutionStrategy()
            pass

        # Default to FastAPI
        from engine.frameworks.fastapi.resolution_strategy import FastAPIResolutionStrategy

        return FastAPIResolutionStrategy()

    @staticmethod
    def create_symbol_resolver(
        project_path: Path,
        import_graph: ImportGraph,
        symbol_index: SymbolIndex,
        framework: str,
    ) -> SymbolResolver:
        """Create SymbolResolver with appropriate framework-specific strategy."""
        strategy = FrameworkFactory.get_resolution_strategy(framework)
        return SymbolResolver(project_path, import_graph, symbol_index, strategy)

    @staticmethod
    def get_filter(
        framework: str,
        project_hash: str,
        project_path: Path,
        parse_cache: ParseCache,
        import_graph,
    ) -> FrameworkFilter:
        """Get the appropriate filter for the framework."""
        if framework == "django":
            return DjangoFilter(project_hash, project_path)

        # Default to FastAPI
        return FastAPIFilter(project_hash, project_path, parse_cache, import_graph)

    @staticmethod
    def get_mapper(
        framework: str,
        core_graph: CoreGraph,
        filter_instance: FrameworkFilter,
        project_hash: str,
        call_graph_result: Optional[CallGraphResult] = None,
        binder: Optional[SymbolResolver] = None,
        query_engine: Optional[QueryEngine] = None,
    ) -> DomainMapper:
        """Get the appropriate domain mapper for the framework."""
        if framework == "django":
            return DjangoDomainMapper(
                core_graph, filter_instance, project_hash, call_graph_result, binder, query_engine
            )

        # Default to FastAPI
        return FastAPIDomainMapper(core_graph, filter_instance, project_hash, call_graph_result, binder, query_engine)

    @staticmethod
    def get_dependency_resolver(
        framework: str,
        binder: SymbolResolver,
        query_engine: QueryEngine,
        project_hash: str,
    ) -> DependencyResolver:
        """Get dependency resolver for the framework."""
        if framework == "django":
            # TODO: Implement DjangoDependencyResolver when Django support is added
            pass

        # Default to FastAPI
        from engine.frameworks.fastapi.dependency_resolver import FastAPIDependencyResolver

        return FastAPIDependencyResolver(binder, query_engine, project_hash)

    @staticmethod
    def get_edge_discoverer(
        framework: str,
        filter_instance: FrameworkFilter,
        binder: SymbolResolver,
        query_engine: QueryEngine,
        parse_cache: ParseCache,
        project_hash: str,
        generic_to_domain_id: dict,
    ) -> EdgeDiscoverer:
        """Get edge discoverer for the framework."""
        if framework == "django":
            # TODO: Implement DjangoEdgeDiscoverer when Django support is added
            pass

        # Default to FastAPI
        from engine.frameworks.fastapi.discovery import FastAPIEdgeDiscoverer

        return FastAPIEdgeDiscoverer(
            filter_instance,
            binder,
            query_engine,
            parse_cache,
            project_hash,
            generic_to_domain_id,
        )
