from pathlib import Path
from typing import Optional

from deepwave_engine.frameworks.base import FrameworkFilter, DomainMapper
from deepwave_engine.frameworks.fastapi.filter import FastAPIFilter
from deepwave_engine.frameworks.fastapi.mapper import FastAPIDomainMapper
from deepwave_engine.frameworks.django.filter import DjangoFilter
from deepwave_engine.frameworks.django.mapper import DjangoDomainMapper
from deepwave_engine.models import CoreGraph
from deepwave_engine.graph.call_graph import CallGraphResult
from deepwave_engine.binder.binder_treesitter import BinderTreeSitter
from deepwave_engine.parser.query_engine import QueryEngine
from deepwave_engine.parser.parse_cache import ParseCache


class FrameworkFactory:
    """Factory for creating framework-specific components."""

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
        binder: Optional[BinderTreeSitter] = None,
        query_engine: Optional[QueryEngine] = None,
    ) -> DomainMapper:
        """Get the appropriate domain mapper for the framework."""
        if framework == "django":
            return DjangoDomainMapper(
                core_graph, filter_instance, project_hash, call_graph_result, binder, query_engine
            )

        # Default to FastAPI
        return FastAPIDomainMapper(core_graph, filter_instance, project_hash, call_graph_result, binder, query_engine)
