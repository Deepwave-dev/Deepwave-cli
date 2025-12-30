from abc import ABC, abstractmethod
from typing import Tuple, List, Optional, Any
from engine.models import CoreGraph
from engine.models import GenericNode
from engine.models import GraphNode, GraphEdge


class FrameworkFilter(ABC):
    """
    Interface for framework-specific filtering of the CoreGraph.
    Identifies framework components like Routers, Apps, and Endpoints.
    """

    # Required attributes for all filters
    services: List[GenericNode]

    @abstractmethod
    def filter(self, core_graph: CoreGraph) -> None:
        """
        Analyze core graph to identify framework patterns.

        Args:
            core_graph: The language-agnostic CoreGraph to analyze
        """
        pass


class DomainMapper(ABC):
    """
    Interface for mapping generic nodes to domain-specific nodes.
    Converts generic classes/functions into specific architectural nodes.
    """

    @abstractmethod
    def map(self) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """
        Map generic nodes to domain nodes and edges.

        Returns:
            Tuple containing lists of Nodes and Edges
        """
        pass
