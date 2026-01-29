"""Flask node mapper for creating domain nodes from generic nodes."""

import re
from pathlib import Path
from typing import Optional

from engine.models import GenericNode, ApplicationNode, RouterNode, EndpointNode, EnumMethod
from engine.frameworks.base import NodeMapper


class FlaskNodeMapper(NodeMapper):
    """Flask-specific node mapping.
    
    Maps GenericNodes from CoreGraph to Flask-specific domain nodes:
    - Flask() instances -> ApplicationNode
    - Blueprint() instances -> RouterNode (reuse FastAPI router type)
    - @app.route() functions -> EndpointNode
    """

    def __init__(self, project_hash: str, project_path: Path):
        self.project_hash = project_hash
        self.project_path = project_path

    def map_entry_point(self, generic_node: GenericNode, project_hash: str, project_path: Path) -> ApplicationNode:
        """Map Flask application instance to ApplicationNode.
        
        Example: app = Flask(__name__) -> ApplicationNode
        
        Args:
            generic_node: GenericNode representing Flask() assignment
            project_hash: Project hash for ID generation
            project_path: Project root path for relative path calculation
            
        Returns:
            ApplicationNode with Flask app metadata
        """
        unique_id = self._get_unique_id_from_generic(generic_node.id)
        relative_path = str(generic_node.file_path.relative_to(project_path))
        
        return ApplicationNode(
            id=f"app.{project_hash}.{unique_id}",
            project_hash=project_hash,
            name=generic_node.name,  # e.g., "app" or "application"
            path=relative_path,
            summary=f"Flask application: {generic_node.name}",
            app_var=generic_node.name,
            start_line=generic_node.start_line,
        )

    def map_routing_config(self, generic_node: GenericNode, project_hash: str, project_path: Path) -> RouterNode:
        """Map Flask Blueprint instance to RouterNode.
        
        Example: bp = Blueprint('users', __name__) -> RouterNode
        
        Blueprints are Flask's routing mechanism, equivalent to FastAPI's APIRouter.
        They're stored as RouterNode for consistency across frameworks.
        
        Args:
            generic_node: GenericNode representing Blueprint() assignment
            project_hash: Project hash for ID generation
            project_path: Project root path for relative path calculation
            
        Returns:
            RouterNode with Blueprint metadata
        """
        unique_id = self._get_unique_id_from_generic(generic_node.id)
        relative_path = str(generic_node.file_path.relative_to(project_path))
        
        # Extract blueprint name from source code if available
        blueprint_name = self._extract_blueprint_name(generic_node)
        
        # Create display name: module.variable (e.g., "users.bp" or "users.users_bp")
        module_name = generic_node.file_path.stem
        display_name = f"{module_name}.{generic_node.name}"
        
        return RouterNode(
            id=f"router.{project_hash}.{unique_id}",
            project_hash=project_hash,
            name=display_name,
            path=relative_path,
            summary=f"Blueprint: {blueprint_name or display_name}",
            router_var=generic_node.name,
            prefix="",  # Will be set from register_blueprint() call in edge discovery
            start_line=generic_node.start_line,
        )

    def map_request_handler(
        self, 
        func_node: GenericNode, 
        decorator_node: Optional[GenericNode], 
        project_hash: str, 
        project_path: Path
    ) -> EndpointNode:
        """Map Flask route handler to EndpointNode.
        
        Examples:
        - @app.route('/users', methods=['GET', 'POST']) def get_users() -> EndpointNode
        - @app.get('/users') def get_users() -> EndpointNode
        - @bp.post('/users') def create_user() -> EndpointNode
        
        Args:
            func_node: GenericNode representing the function
            decorator_node: GenericNode representing the route decorator
            project_hash: Project hash for ID generation
            project_path: Project root path for relative path calculation
            
        Returns:
            EndpointNode with route metadata
        """
        unique_id = self._get_unique_id_from_generic(func_node.id)
        relative_path = str(func_node.file_path.relative_to(project_path))
        
        # Determine HTTP method
        http_method = self._extract_http_method(decorator_node)
        
        return EndpointNode(
            id=f"endpoint.{project_hash}.{unique_id}",
            project_hash=project_hash,
            name=func_node.name,
            path=relative_path,
            summary=f"Endpoint: {func_node.name}",
            method=http_method,
            start_line=func_node.start_line,
            end_line=func_node.end_line,
            code_chunk=func_node.source_code,
        )

    def _get_unique_id_from_generic(self, generic_id: str) -> str:
        """Extract unique identifier from generic node ID.
        
        Generic IDs are typically: "project_hash:node_type:hash123"
        We extract the hash portion for uniqueness.
        
        Args:
            generic_id: Full generic node ID
            
        Returns:
            Unique hash portion of the ID
        """
        parts = generic_id.split(":")
        if len(parts) >= 3:
            return parts[2]  # Return the hash portion
        # Fallback: use the full ID if format is unexpected
        return generic_id.replace(":", "_")

    def _extract_blueprint_name(self, generic_node: GenericNode) -> Optional[str]:
        """Extract blueprint name from Blueprint() instantiation.
        
        Example: bp = Blueprint('users', __name__) -> 'users'
        
        Args:
            generic_node: GenericNode with Blueprint() source code
            
        Returns:
            Blueprint name string if found, None otherwise
        """
        if not generic_node.source_code:
            return None
        
        # Look for Blueprint('name', ...) pattern
        match = re.search(r"Blueprint\s*\(\s*['\"]([^'\"]+)['\"]", generic_node.source_code)
        if match:
            return match.group(1)
        
        return None

    def _extract_http_method(self, decorator_node: Optional[GenericNode]) -> EnumMethod:
        """Extract HTTP method from Flask route decorator.
        
        Handles:
        - @app.route('/path', methods=['GET', 'POST']) -> GET (first method)
        - @app.get('/path') -> GET
        - @app.post('/path') -> POST
        - No decorator -> GET (default)
        
        Args:
            decorator_node: GenericNode representing the decorator
            
        Returns:
            EnumMethod enum value
        """
        if not decorator_node or not decorator_node.name:
            return EnumMethod.GET
        
        # Parse decorator name: "app.route", "app.get", "bp.post", etc.
        parts = decorator_node.name.split(".")
        if len(parts) < 2:
            return EnumMethod.GET
        
        method_name = parts[1].lower()
        
        # Check for new-style HTTP method decorators (Flask 2.0+)
        method_map = {
            "get": EnumMethod.GET,
            "post": EnumMethod.POST,
            "put": EnumMethod.PUT,
            "delete": EnumMethod.DELETE,
            "patch": EnumMethod.PATCH,
            "head": EnumMethod.HEAD,
            "options": EnumMethod.OPTIONS,
        }
        
        if method_name in method_map:
            return method_map[method_name]
        
        # For old-style @app.route(), extract from methods parameter
        if method_name == "route":
            return self._extract_method_from_route_decorator(decorator_node)
        
        return EnumMethod.GET

    def _extract_method_from_route_decorator(self, decorator_node: GenericNode) -> EnumMethod:
        """Extract HTTP method from @app.route() methods parameter.
        
        Examples:
        - @app.route('/path', methods=['GET']) -> GET
        - @app.route('/path', methods=['POST', 'PUT']) -> POST (first method)
        - @app.route('/path') -> GET (default)
        
        Args:
            decorator_node: GenericNode with route decorator source code
            
        Returns:
            EnumMethod enum value
        """
        if not decorator_node.source_code:
            return EnumMethod.GET
        
        # Look for methods=['GET', 'POST'] pattern
        methods_match = re.search(
            r"methods\s*=\s*\[(.*?)\]", 
            decorator_node.source_code, 
            re.DOTALL
        )
        
        if methods_match:
            methods_str = methods_match.group(1)
            # Extract first quoted method name
            method_names = re.findall(r"['\"](\w+)['\"]", methods_str)
            if method_names:
                first_method = method_names[0].upper()
                # Map string to enum
                method_map = {
                    "GET": EnumMethod.GET,
                    "POST": EnumMethod.POST,
                    "PUT": EnumMethod.PUT,
                    "DELETE": EnumMethod.DELETE,
                    "PATCH": EnumMethod.PATCH,
                    "HEAD": EnumMethod.HEAD,
                    "OPTIONS": EnumMethod.OPTIONS,
                }
                return method_map.get(first_method, EnumMethod.GET)
        
        # Default to GET if no methods specified
        return EnumMethod.GET
