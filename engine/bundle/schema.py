"""Bundle schema - contract between CLI and backend."""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from ..models import ServiceGraph, CodebaseStats


class Manifest(BaseModel):
    """Bundle manifest metadata."""

    bundle_version: str = Field(default="1.0.0")
    tool_version: str
    repo_root: str
    commit_sha: str
    created_at: str


class Bundle(BaseModel):
    """Complete bundle containing all analysis results."""

    manifest: Manifest
    graph: ServiceGraph
    chunks: List[Dict[str, Any]] = Field(default_factory=list)
    stats: CodebaseStats
    file_tree: Optional[Dict[str, Any]] = Field(default=None, description="File tree structure optimized for LLM consumption")
