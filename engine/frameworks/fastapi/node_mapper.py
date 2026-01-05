"""FastAPI node mapper for creating domain nodes from generic nodes."""

from pathlib import Path
from typing import Optional

from engine.models import GenericNode, ApplicationNode, RouterNode, EndpointNode, EnumMethod
from engine.frameworks.base import NodeMapper


class FastAPINodeMapper(NodeMapper):
    """FastAPI-specific node mapping."""

    def __init__(self, project_hash: str, project_path: Path):
        self.project_hash = project_hash
        self.project_path = project_path

    def map_entry_point(self, generic_node: GenericNode, project_hash: str, project_path: Path) -> ApplicationNode:
        """Map FastAPI application instance to ApplicationNode."""
        unique_id = self._get_unique_id_from_generic(generic_node.id)
        return ApplicationNode(
            id=f"app.{project_hash}.{unique_id}",
            project_hash=project_hash,
            name=generic_node.name,
            path=str(generic_node.file_path.relative_to(project_path)),
            summary=f"FastAPI application: {generic_node.name}",
            app_var=generic_node.name,
            start_line=generic_node.start_line,
        )

    def map_routing_config(self, generic_node: GenericNode, project_hash: str, project_path: Path) -> RouterNode:
        """Map FastAPI APIRouter instance to RouterNode."""
        unique_id = self._get_unique_id_from_generic(generic_node.id)
        module_name = generic_node.file_path.stem
        display_name = f"{module_name}.{generic_node.name}"

        return RouterNode(
            id=f"router.{project_hash}.{unique_id}",
            project_hash=project_hash,
            name=display_name,
            path=str(generic_node.file_path.relative_to(project_path)),
            summary=f"API Router: {display_name}",
            router_var=generic_node.name,
            prefix="",
            start_line=generic_node.start_line,
        )

    def map_request_handler(
        self, func_node: GenericNode, decorator_node: Optional[GenericNode], project_hash: str, project_path: Path
    ) -> EndpointNode:
        """Map FastAPI endpoint handler to EndpointNode."""
        if not decorator_node:
            # Fallback if no decorator provided
            http_method_str = "GET"
        else:
            decorator_parts = decorator_node.name.split(".")
            http_method_str = decorator_parts[1].upper() if len(decorator_parts) >= 2 else "GET"

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
        return EndpointNode(
            id=f"endpoint.{project_hash}.{unique_id}",
            project_hash=project_hash,
            name=func_node.name,
            path=str(func_node.file_path.relative_to(project_path)),
            summary=f"Endpoint: {func_node.name}",
            method=http_method,
            start_line=func_node.start_line,
            end_line=func_node.end_line,
            code_chunk=func_node.source_code,
        )

    def _get_unique_id_from_generic(self, generic_id: str) -> str:
        """Extract unique identifier from generic node ID."""
        parts = generic_id.split(":")
        return parts[2] if len(parts) >= 3 else generic_id.replace(":", "_")
