"""FastAPI pattern matcher for identifying framework-specific patterns."""

import re
from typing import List, Optional, Dict, Any
from pathlib import Path

import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from engine.models import CoreGraph, GenericNode
from engine.frameworks.base import BasePatternMatcher


class FastAPIPatternMatcher(BasePatternMatcher):
    """FastAPI-specific pattern matching."""

    def _matches_call_pattern(self, node: GenericNode, symbol_name: str, module_name: str) -> bool:
        """Generic helper to detect call pattern."""
        if (
            not node.source_code
            or self.is_test_file(node.file_path)
            or self._is_string_literal_assignment(node.source_code)
        ):
            return False
        match = re.search(r"=\s*(\w+)\s*\(", node.source_code)
        if not match:
            return False
        symbol = match.group(1)
        if symbol == symbol_name:
            return True
        module, original = self._resolve_symbol(node.file_path, symbol)
        return module == module_name and original == symbol_name

    def is_application_instance(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect FastAPI() application instantiation."""
        return self._matches_call_pattern(node, "FastAPI", "fastapi")

    def get_application_imports(self) -> List[str]:
        """Return required imports for FastAPI application."""
        return ["FastAPI", "fastapi"]

    def is_routing_configuration(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect APIRouter() instantiation."""
        return self._matches_call_pattern(node, "APIRouter", "fastapi")

    def get_routing_imports(self) -> List[str]:
        """Return required imports for APIRouter."""
        return ["APIRouter", "fastapi"]

    def is_request_handler(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """Detect FastAPI endpoint handlers with decorators."""
        # Find decorators for this function
        from engine.models import GenericEdgeType

        decorates_edges = core_graph.get_edges_to_node(node.id)
        for edge in decorates_edges:
            if edge.edge_type != GenericEdgeType.DECORATES:
                continue

            decorator_node = core_graph.get_node(edge.source_id)
            if not decorator_node:
                continue

            # Check if this is a router HTTP method decorator
            if self._is_router_decorator(decorator_node):
                method, path = self._extract_method_and_path(decorator_node, node)
                return {"http_method": method, "path": path, "handler_type": "function", "decorator": decorator_node}

        return None

    def get_handler_imports(self) -> List[str]:
        """Return required imports for handler validation."""
        return ["fastapi"]

    def is_dependency_injection(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """Detect FastAPI Depends() patterns."""
        # This is handled by the filter's dependency detection logic
        # Return None here as DI detection is more complex and handled elsewhere
        return None

    def get_dependency_imports(self) -> List[str]:
        """Return required imports for Depends."""
        return ["fastapi"]

    def is_service_component(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect service classes (handled by filter's service detection)."""
        return False

    def get_service_imports(self) -> List[str]:
        """Return required imports for service validation."""
        return []

    def is_middleware(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect FastAPI middleware patterns."""
        return False

    def get_framework_name(self) -> str:
        """Return framework name."""
        return "fastapi"

    def get_language(self) -> str:
        """Return programming language."""
        return "python"

    def _is_router_decorator(self, decorator_node: GenericNode) -> bool:
        """Check if decorator is a router HTTP method decorator."""
        if not decorator_node.name or "." not in decorator_node.name:
            return False
        parts = decorator_node.name.split(".")
        if len(parts) != 2:
            return False
        http_methods = ["get", "post", "put", "delete", "patch", "options", "head", "trace"]
        return parts[1].lower() in http_methods

    def _extract_method_and_path(self, decorator_node: GenericNode, func_node: GenericNode) -> tuple:
        """Extract HTTP method and path from decorator."""
        parts = decorator_node.name.split(".")
        method = parts[1].upper() if len(parts) >= 2 else "GET"

        # Try to extract path from decorator source code
        path = None
        if decorator_node.source_code:
            path_match = re.search(r'["\']([^"\']+)["\']', decorator_node.source_code)
            if path_match:
                path = path_match.group(1)

        return method, path
