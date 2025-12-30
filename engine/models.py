"""
Core models for the Deepwave Engine.

These are simplified versions of the backend models, without database dependencies.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum
from pydantic import BaseModel, Field


# ============================================================================
# Generic Graph Models (Language-agnostic)
# ============================================================================


class GenericNodeType(str, Enum):
    """Generic node types that apply across all languages"""

    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    ASSIGNMENT = "assignment"
    IMPORT = "import"
    MODULE = "module"
    DECORATOR = "decorator"
    UNKNOWN = "unknown"


class GenericEdgeType(str, Enum):
    """Generic edge types that apply across all languages"""

    CONTAINS = "contains"
    INHERITS = "inherits"
    CALLS = "calls"
    INSTANTIATES = "instantiates"
    IMPORTS = "imports"
    REFERENCES = "references"
    DECORATES = "decorates"
    ASSIGNS_TO = "assigns_to"
    UNKNOWN = "unknown"


@dataclass
class GenericNode:
    """Generic representation of a code construct."""

    id: str
    node_type: GenericNodeType
    name: str
    file_path: Path
    start_line: int
    end_line: int
    start_byte: int = 0
    end_byte: int = 0
    source_code: Optional[str] = None
    doc: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None
    child_ids: List[str] = field(default_factory=list)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, GenericNode):
            return False
        return self.id == other.id


@dataclass
class GenericEdge:
    """Generic representation of a relationship between code constructs."""

    id: str
    edge_type: GenericEdgeType
    source_id: str
    target_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, GenericEdge):
            return False
        return self.id == other.id


@dataclass
class CoreGraph:
    """Core generic graph representing the complete code structure."""

    project_path: Path
    project_hash: str
    nodes: Dict[str, GenericNode] = field(default_factory=dict)  # id -> node
    edges: Dict[str, GenericEdge] = field(default_factory=dict)  # id -> edge

    # Indices for fast lookup
    nodes_by_file: Dict[Path, List[str]] = field(default_factory=dict)  # file -> [node_ids]
    nodes_by_type: Dict[GenericNodeType, List[str]] = field(default_factory=dict)  # type -> [node_ids]
    nodes_by_name: Dict[str, List[str]] = field(default_factory=dict)  # name -> [node_ids]

    edges_by_type: Dict[GenericEdgeType, List[str]] = field(default_factory=dict)  # type -> [edge_ids]
    edges_from_node: Dict[str, List[str]] = field(default_factory=dict)  # node_id -> [edge_ids]
    edges_to_node: Dict[str, List[str]] = field(default_factory=dict)  # node_id -> [edge_ids]

    def add_node(self, node: GenericNode) -> None:
        """Add a node to the graph and update indices"""
        self.nodes[node.id] = node

        # Update file index
        if node.file_path not in self.nodes_by_file:
            self.nodes_by_file[node.file_path] = []
        if node.id not in self.nodes_by_file[node.file_path]:
            self.nodes_by_file[node.file_path].append(node.id)

        # Update type index
        if node.node_type not in self.nodes_by_type:
            self.nodes_by_type[node.node_type] = []
        if node.id not in self.nodes_by_type[node.node_type]:
            self.nodes_by_type[node.node_type].append(node.id)

        # Update name index
        if node.name not in self.nodes_by_name:
            self.nodes_by_name[node.name] = []
        if node.id not in self.nodes_by_name[node.name]:
            self.nodes_by_name[node.name].append(node.id)

    def add_edge(self, edge: GenericEdge) -> None:
        """Add an edge to the graph and update indices"""
        self.edges[edge.id] = edge

        # Update type index
        if edge.edge_type not in self.edges_by_type:
            self.edges_by_type[edge.edge_type] = []
        if edge.id not in self.edges_by_type[edge.edge_type]:
            self.edges_by_type[edge.edge_type].append(edge.id)

        # Update source index
        if edge.source_id not in self.edges_from_node:
            self.edges_from_node[edge.source_id] = []
        if edge.id not in self.edges_from_node[edge.source_id]:
            self.edges_from_node[edge.source_id].append(edge.id)

        # Update target index
        if edge.target_id not in self.edges_to_node:
            self.edges_to_node[edge.target_id] = []
        if edge.id not in self.edges_to_node[edge.target_id]:
            self.edges_to_node[edge.target_id].append(edge.id)

    def get_node(self, node_id: str) -> Optional[GenericNode]:
        """Get a node by ID"""
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GenericEdge]:
        """Get an edge by ID"""
        return self.edges.get(edge_id)

    def get_nodes_by_type(self, node_type: GenericNodeType) -> List[GenericNode]:
        """Get all nodes of a specific type"""
        node_ids = self.nodes_by_type.get(node_type, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def get_nodes_by_file(self, file_path: Path) -> List[GenericNode]:
        """Get all nodes in a specific file"""
        node_ids = self.nodes_by_file.get(file_path, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def get_nodes_by_name(self, name: str) -> List[GenericNode]:
        """Get all nodes with a specific name"""
        node_ids = self.nodes_by_name.get(name, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def get_edges_by_type(self, edge_type: GenericEdgeType) -> List[GenericEdge]:
        """Get all edges of a specific type"""
        edge_ids = self.edges_by_type.get(edge_type, [])
        return [self.edges[eid] for eid in edge_ids if eid in self.edges]

    def get_edges_from_node(self, node_id: str) -> List[GenericEdge]:
        """Get all edges originating from a node"""
        edge_ids = self.edges_from_node.get(node_id, [])
        return [self.edges[eid] for eid in edge_ids if eid in self.edges]

    def get_edges_to_node(self, node_id: str) -> List[GenericEdge]:
        """Get all edges pointing to a node"""
        edge_ids = self.edges_to_node.get(node_id, [])
        return [self.edges[eid] for eid in edge_ids if eid in self.edges]

    def get_children(self, node_id: str) -> List[GenericNode]:
        """Get all child nodes of a node"""
        node = self.get_node(node_id)
        if not node:
            return []
        return [self.nodes[cid] for cid in node.child_ids if cid in self.nodes]

    def get_parent(self, node_id: str) -> Optional[GenericNode]:
        """Get the parent node of a node"""
        node = self.get_node(node_id)
        if not node or not node.parent_id:
            return None
        return self.get_node(node.parent_id)

    def get_node_by_id(self, node_id: str) -> Optional[GenericNode]:
        """Get a node by its ID (alias for get_node)"""
        return self.get_node(node_id)


# ============================================================================
# File Models
# ============================================================================


class FileDetail(BaseModel):
    """Details about a file in the repository"""

    path: str = Field(..., description="File path relative to repository root")
    language: str = Field(..., description="Programming language")
    size_bytes: int = Field(..., description="File size in bytes")
    line_count: int = Field(..., description="Number of lines in the file")


# ============================================================================
# Project Metadata
# ============================================================================


class ProjectMetadata(BaseModel):
    """Project metadata"""

    project_hash: str = Field(..., description="Unique project identifier")
    repository_url: str = Field(..., description="Repository URL")
    repository_name: str = Field(..., description="Repository name")
    branch: str = Field(..., description="Branch name")
    commit_sha: str = Field(..., description="Commit SHA")
    parsed_at: str = Field(..., description="Analysis timestamp")


# ============================================================================
# Domain Graph Models (Framework-specific)
# ============================================================================


class EdgeRelation(str, Enum):
    """Allowed relations between nodes in the graph."""

    includes = "includes"
    has_endpoint = "has_endpoint"
    contains = "contains"
    exposes = "exposes"
    calls = "calls"
    calls_function = "calls_function"
    guarded_by = "guarded_by"
    depends_on = "depends_on"
    cached_by = "cached_by"
    initializes = "initializes"
    inherits = "inherits"
    uses = "uses"


# ============================================================================
# Domain-Specific Node Types (Framework-specific)
# ============================================================================


class EnumMethod(str, Enum):
    """HTTP methods"""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class NodeType(str, Enum):
    """Domain-specific node types"""

    application = "application"
    router = "router"
    endpoint = "endpoint"
    dependency = "dependency"
    service_class = "service_class"
    method = "method"
    function = "function"
    entry_point = "entry_point"
    data_model = "data_model"


class BaseNode(BaseModel):
    """Base class for all graph nodes"""

    id: str
    project_hash: str
    type: NodeType
    name: str
    path: str
    summary: str = Field(default="", description="Description/documentation")
    doc: Optional[str] = None


class ApplicationNode(BaseNode):
    """Node representing a FastAPI service/app"""

    type: NodeType = NodeType.application
    app_var: str = ""
    start_line: int = 1


class RouterNode(BaseNode):
    """Node representing an APIRouter instance"""

    type: NodeType = NodeType.router
    router_var: str = ""
    prefix: Optional[str] = None
    start_line: int = 1


class ServiceClassNode(BaseNode):
    """Node representing a service class"""

    type: NodeType = NodeType.service_class
    class_name: str = ""
    module_path: str = ""
    methods: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    start_line: int = 1
    parent_class: Optional[str] = Field(
        default=None, description="Name of parent class if this class inherits from another"
    )
    inheritance_children: List[str] = Field(
        default_factory=list, description="List of child class node IDs that inherit from this class"
    )


class MethodNode(BaseNode):
    """Node representing a method"""

    type: NodeType = NodeType.method
    arguments: List[Dict[str, Any]] = Field(default_factory=list)
    return_type: Optional[Dict[str, Any]] = None
    is_async: bool = False
    is_private: bool = False
    start_line: int = 1
    end_line: Optional[int] = None


class FunctionNode(BaseNode):
    """Node representing a function"""

    type: NodeType = NodeType.function
    function_name: str = ""
    start_line: int = 1
    end_line: Optional[int] = None
    is_async: bool = False
    parent_class: Optional[str] = None

    @classmethod
    def from_generic_node(
        cls,
        generic_node: "GenericNode",
        project_path: Path,
        project_hash: str,
    ) -> "FunctionNode":
        """Create FunctionNode from GenericNode."""
        is_async = "async def" in (generic_node.source_code or "")
        relative_path = str(generic_node.file_path.relative_to(project_path))

        # Extract unique ID from generic node
        unique_id = generic_node.id.split(".")[-1] if "." in generic_node.id else generic_node.id
        func_id = f"function.{project_hash}.{unique_id}"

        return cls(
            id=func_id,
            project_hash=project_hash,
            type=NodeType.function,
            name=generic_node.name,
            path=relative_path,
            summary=f"Function: {generic_node.name}",
            function_name=generic_node.name,
            start_line=generic_node.start_line,
            end_line=generic_node.end_line,
            is_async=is_async,
        )


class EndpointNode(BaseNode):
    """Node representing an HTTP endpoint"""

    type: NodeType = NodeType.endpoint
    method: EnumMethod = Field(default=EnumMethod.GET)  # HTTP method
    start_line: int = 1
    end_line: Optional[int] = None
    code_chunk: Optional[str] = None


class EntryPointNode(BaseNode):
    """Node representing an entry point"""

    type: NodeType = NodeType.entry_point
    start_line: int = 1
    end_line: Optional[int] = None


# Alias for compatibility
GraphNode = BaseNode  # For backward compatibility


class GraphEdge(BaseModel):
    """Edge representing a relationship between nodes"""

    id: str
    src_id: str
    dst_id: str
    relation: EdgeRelation
    project_hash: str


# Union type for all node types
GraphNode = Union[
    ApplicationNode,
    RouterNode,
    ServiceClassNode,
    MethodNode,
    FunctionNode,
    EndpointNode,
    EntryPointNode,
    BaseNode,
]


class ServiceGraph(BaseModel):
    """Complete service graph representation"""

    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: ProjectMetadata


# ============================================================================
# Stats Models
# ============================================================================


class KeyModule(BaseModel):
    """Represents a key service module"""

    id: str
    name: str
    dependent_count: int
    path: str


class CodebaseStats(BaseModel):
    """Comprehensive codebase statistics"""

    total_files: int
    total_lines_of_code: int
    languages: List[str]
    frameworks: List[str]
    total_nodes: int
    applications: int
    routers: int
    endpoints: int
    services: int
    methods: int
    key_modules: List[KeyModule] = Field(default_factory=list)
