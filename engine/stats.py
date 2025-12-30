from collections import defaultdict
from typing import Dict, List

from engine.models import GraphEdge, GraphNode, ServiceGraph
from engine.models import FileDetail
from engine.models import CodebaseStats, KeyModule


class StatsCalculator:
    """Calculates comprehensive codebase statistics"""

    @staticmethod
    def calculate(
        service_graph: ServiceGraph,
        file_details: List[FileDetail],
        framework: str,
    ) -> CodebaseStats:
        """Calculate all codebase statistics"""

        # Count node types
        node_counts = StatsCalculator._count_nodes_by_type(service_graph.nodes)

        # Calculate key modules (top services by incoming edges)
        key_modules = StatsCalculator._calculate_key_modules(service_graph.nodes, service_graph.edges, top_n=5)

        # Calculate total lines of code
        total_lines = sum(f.line_count for f in file_details)

        # Extract languages (unique set from files)
        languages = list({f.language for f in file_details if f.language != "unknown"})

        # Handle frameworks: store as array for flexibility
        # Current: single framework detected, but array allows for future monorepos
        # Filter out "unknown" - only store detected frameworks
        frameworks_list = [framework] if framework != "unknown" else []

        return CodebaseStats(
            total_files=len(file_details),
            total_lines_of_code=total_lines,
            languages=languages,
            frameworks=frameworks_list,
            total_nodes=len(service_graph.nodes),
            applications=node_counts.get("application", 0),
            routers=node_counts.get("router", 0),
            endpoints=node_counts.get("endpoint", 0),
            services=node_counts.get("service_class", 0),
            methods=node_counts.get("method", 0),
            key_modules=key_modules,
        )

    @staticmethod
    def _count_nodes_by_type(nodes: List[GraphNode]) -> Dict[str, int]:
        """Count nodes by their type"""
        counts = defaultdict(int)
        for node in nodes:
            counts[node.type] += 1
        return dict(counts)

    @staticmethod
    def _calculate_key_modules(nodes: List[GraphNode], edges: List[GraphEdge], top_n: int = 5) -> List[KeyModule]:
        """Calculate top service nodes by incoming dependency edges"""
        # Count incoming edges per service node
        incoming_edges = defaultdict(int)
        service_nodes = {node.id: node for node in nodes if node.type == "service_class"}

        # Count dependencies (edges pointing TO service nodes)
        for edge in edges:
            if edge.dst_id in service_nodes:
                # Count depends_on, calls, and other dependency-like edges
                if edge.relation.value in ["depends_on", "calls", "calls_function"]:
                    incoming_edges[edge.dst_id] += 1

        # Sort by dependency count and get top N
        sorted_services = sorted(incoming_edges.items(), key=lambda x: x[1], reverse=True)[:top_n]

        # Build KeyModule objects
        key_modules = []
        for node_id, incoming_count in sorted_services:
            node = service_nodes[node_id]
            key_modules.append(
                KeyModule(
                    id=node_id,
                    name=getattr(node, "class_name", getattr(node, "name", node_id)),
                    dependent_count=incoming_count,  # How many things depend ON this service
                    path=getattr(node, "path", ""),
                )
            )

        return key_modules
