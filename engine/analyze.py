"""Main entry point for repository analysis."""

from pathlib import Path
from typing import Dict, Any, List

from .models import AnalysisResult, ServiceGraph, CodebaseStats, ProjectMetadata
from .graph.extractor import scan_repository
from .graph.core_graph import CoreGraphBuilder
from .graph.call_graph import CallGraphBuilderTreeSitter
from .parser import TreeSitterParser, QueryEngine
from .parser.parse_cache import ParseCache
from .frameworks.detector import FrameworkDetector
from .frameworks.factory import FrameworkFactory
from .binder.import_graph import ImportGraph
from .binder.symbol_index import SymbolIndex
from .binder.symbol_resolver import SymbolResolver
from .stats import StatsCalculator


def extract_graph(repo_path: Path, project_metadata: ProjectMetadata) -> tuple[ServiceGraph, str]:
    """Extract service graph from repository. Returns (graph, framework)."""
    files_metadata = scan_repository(repo_path)
    python_paths = [repo_path / file.path for file in files_metadata if file.language == "python"]

    parser = TreeSitterParser("python")
    parse_cache = ParseCache(repo_path, parser)
    query_engine = QueryEngine(parser)

    core_builder = CoreGraphBuilder(project_metadata, repo_path, parse_cache)
    core_graph = core_builder.build_graph(files=python_paths)

    import_graph = ImportGraph(repo_path, parse_cache)
    import_graph.build(python_paths)

    framework_detector = FrameworkDetector()
    framework = framework_detector.detect(repo_path)
    framework_filter = FrameworkFactory.get_filter(
        framework, project_metadata.project_hash, repo_path, parse_cache, import_graph
    )
    framework_filter.filter(core_graph)

    symbol_index = SymbolIndex(project_metadata.project_hash, repo_path, import_graph, parse_cache)
    symbol_index.index_services(framework_filter.services)
    symbol_index.build_instance_index(python_paths)
    binder = FrameworkFactory.create_symbol_resolver(repo_path, import_graph, symbol_index, framework)

    call_graph_builder = CallGraphBuilderTreeSitter(
        project_metadata.project_hash, repo_path, core_graph, binder, parse_cache
    )
    call_graph_result = call_graph_builder.build(python_paths)

    domain_mapper = FrameworkFactory.get_mapper(
        framework,
        core_graph,
        framework_filter,
        project_metadata.project_hash,
        call_graph_result,
        binder,
        query_engine,
    )

    nodes, edges = domain_mapper.map()
    service_graph = ServiceGraph(nodes=nodes, edges=edges, metadata=project_metadata)

    return service_graph, framework


def calculate_stats(graph: ServiceGraph, files_metadata: List, framework: str) -> CodebaseStats:
    """Calculate codebase statistics."""
    return StatsCalculator.calculate(graph, files_metadata, framework)


def analyze_repo(repo_path: str, project_metadata: ProjectMetadata) -> AnalysisResult:
    """Pure function to analyze a repository."""
    repo_path_obj = Path(repo_path)
    if not repo_path_obj.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    if not repo_path_obj.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo_path}")

    files_metadata = scan_repository(repo_path_obj)
    graph, framework = extract_graph(repo_path_obj, project_metadata)
    stats = calculate_stats(graph, files_metadata, framework)

    return AnalysisResult(graph=graph, stats=stats, files=files_metadata, framework=framework)
