"""Flask pattern matcher for identifying framework-specific patterns."""

import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from engine.models import CoreGraph, GenericNode, GenericNodeType
from engine.frameworks.base import BasePatternMatcher


class FlaskPatternMatcher(BasePatternMatcher):
    """Flask-specific pattern matching.
    
    Detects Flask patterns including:
    - Flask() application instances and subclasses
    - Application factory functions (create_app)
    - Blueprint() instances
    - Route decorators (@app.route, @bp.route, @app.get, etc.)
    - MethodView class-based views
    - Error handlers (@app.errorhandler)
    - Lifecycle hooks (@app.before_request, @app.after_request, etc.)
    - Flask extension instantiation (SQLAlchemy, Migrate, etc.)
    """

    def _matches_call_pattern(self, node: GenericNode, symbol_name: str, module_name: str) -> bool:
        """Generic helper to detect call pattern (e.g., Flask(), Blueprint())."""
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
        
        # Resolve through import graph
        module, original = self._resolve_symbol(node.file_path, symbol)
        return module == module_name and original == symbol_name

    def is_application_instance(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect Flask() application instantiation or Flask subclass instantiation.
        
        Examples:
        - app = Flask(__name__)  # Direct instantiation
        - application = Flask(__name__)
        - app = Redash()  # Flask subclass (Redash inherits from Flask)
        - app = CustomFlask()  # Any Flask subclass
        """
        # Strategy 1: Direct Flask() instantiation
        if self._matches_call_pattern(node, "Flask", "flask"):
            return True
        
        # Strategy 2: Flask subclass instantiation
        # Check if this is instantiating a Flask subclass
        return self._is_flask_subclass_instantiation(node, core_graph)

    def get_application_imports(self) -> List[str]:
        """Return required imports for Flask application."""
        return ["Flask", "flask"]

    def is_routing_configuration(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect Blueprint() instantiation.
        
        Examples:
        - bp = Blueprint('users', __name__)
        - users_bp = Blueprint('users', __name__)
        """
        return self._matches_call_pattern(node, "Blueprint", "flask")

    def get_routing_imports(self) -> List[str]:
        """Return required imports for Flask blueprints."""
        return ["Blueprint", "flask"]

    def is_request_handler(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """Detect Flask endpoint handlers with decorators.
        
        Supports:
        - @app.route('/path', methods=['GET', 'POST'])
        - @app.get('/path'), @app.post('/path'), etc. (Flask 2.0+)
        - @bp.route('/path')
        
        Returns dict with handler metadata or None if not a handler:
        {
            'http_method': 'GET' | 'POST' | 'ALL' | etc.,
            'path': '/users/{id}' or None,
            'handler_type': 'function',
            'decorator': decorator_node
        }
        """
        from engine.models import GenericEdgeType

        # Find decorators for this function
        decorates_edges = core_graph.get_edges_to_node(node.id)
        for edge in decorates_edges:
            if edge.edge_type != GenericEdgeType.DECORATES:
                continue

            decorator_node = core_graph.get_node(edge.source_id)
            if not decorator_node:
                continue

            # Check if this is a Flask route decorator
            if self._is_route_decorator(decorator_node):
                method, path = self._extract_method_and_path(decorator_node, node)
                return {
                    "http_method": method,
                    "path": path,
                    "handler_type": "function",
                    "decorator": decorator_node,
                }

        return None

    def get_handler_imports(self) -> List[str]:
        """Return required imports for Flask handlers."""
        return ["flask"]

    def is_dependency_injection(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """Detect Flask dependency injection patterns.
        
        Flask doesn't have formal DI like FastAPI, but supports:
        - Flask-Injector @inject decorator
        - Manual factory functions
        - g object pattern
        
        Returns None as Flask DI is handled separately in DependencyResolver.
        """
        return None

    def get_dependency_imports(self) -> List[str]:
        """Flask doesn't use explicit DI like FastAPI."""
        return []

    def is_service_component(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect Flask service classes.
        
        Flask services are identified using the same heuristics as FastAPI:
        - Classes with instance methods
        - Excluding Pydantic models, dataclasses, ABCs
        
        This is handled by the Filter's service detection logic.
        """
        return False

    def get_service_imports(self) -> List[str]:
        """Return required imports for Flask services."""
        return []

    def is_middleware(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect Flask middleware patterns.
        
        Flask middleware is typically implemented as:
        - @app.before_request
        - @app.after_request
        - Custom WSGI middleware
        
        Handled separately via hook detection.
        """
        return False

    def get_framework_name(self) -> str:
        """Return framework name."""
        return "flask"

    def get_language(self) -> str:
        """Return programming language."""
        return "python"
    
    def _is_flask_subclass_instantiation(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if node is instantiating a Flask subclass.
        
        Detects patterns like:
        - app = Redash() where class Redash(Flask): ...
        - app = CustomApp() where class CustomApp(Flask): ...
        
        This is critical for production apps that extend Flask.
        
        Args:
            node: Assignment node to check
            core_graph: Core graph for looking up class definitions
            
        Returns:
            True if instantiating a Flask subclass, False otherwise
        """
        if not node.source_code or self.is_test_file(node.file_path):
            return False
        
        # Extract class name from instantiation: "app = ClassName()"
        match = re.search(r"=\s*(\w+)\s*\(", node.source_code)
        if not match:
            return False
        
        class_name = match.group(1)
        
        # Quick check: class name should be capitalized (heuristic)
        if not class_name[0].isupper():
            return False
        
        # Don't re-detect direct Flask() calls
        if class_name == "Flask":
            return False
        
        # Look for class definition in the same file
        if self._class_inherits_from_flask(node.file_path, class_name, core_graph):
            return True
        
        # Check if class is imported and inherits from Flask
        module, original = self._resolve_symbol(node.file_path, class_name)
        if module and original:
            # Try to find the class definition in the source module
            source_file = self.import_graph.file_for_module(module)
            if source_file:
                return self._class_inherits_from_flask(source_file, original or class_name, core_graph)
        
        return False
    
    def _class_inherits_from_flask(self, file_path: Path, class_name: str, core_graph: CoreGraph) -> bool:
        """Check if a class inherits from Flask.
        
        Args:
            file_path: File containing the class
            class_name: Name of the class to check
            core_graph: Core graph to search for class definitions
            
        Returns:
            True if class inherits from Flask, False otherwise
        """
        # Find all class nodes in the file
        all_classes = core_graph.get_nodes_by_type(GenericNodeType.CLASS)
        
        for class_node in all_classes:
            # Match by name and file
            if class_node.name != class_name:
                continue
            if class_node.file_path != file_path:
                continue
            
            # Check base classes in metadata
            base_classes = class_node.metadata.get("base_classes", [])
            
            # Direct inheritance: class Redash(Flask):
            if "Flask" in base_classes:
                return True
            
            # Could be imported: class Redash(flask.Flask):
            for base in base_classes:
                if "Flask" in base or base.endswith(".Flask"):
                    return True
        
        return False

    def _is_route_decorator(self, decorator_node: GenericNode) -> bool:
        """Check if decorator is a Flask route decorator.
        
        Matches:
        - app.route, bp.route
        - app.get, app.post, app.put, app.delete, app.patch (Flask 2.0+)
        - bp.get, bp.post, etc.
        """
        if not decorator_node.name or "." not in decorator_node.name:
            return False
        
        parts = decorator_node.name.split(".")
        if len(parts) != 2:
            return False
        
        method = parts[1].lower()
        
        # Check for .route() decorator
        if method == "route":
            return True
        
        # Check for HTTP method decorators (Flask 2.0+)
        http_methods = ["get", "post", "put", "delete", "patch", "head", "options"]
        return method in http_methods

    def _extract_method_and_path(self, decorator_node: GenericNode, func_node: GenericNode) -> tuple:
        """Extract HTTP method and path from Flask decorator.
        
        Handles:
        - @app.route('/users', methods=['GET', 'POST'])
        - @app.get('/users')
        - @bp.post('/users')
        """
        parts = decorator_node.name.split(".")
        method_name = parts[1].lower() if len(parts) >= 2 else "route"
        
        # Determine HTTP method
        if method_name in ["get", "post", "put", "delete", "patch", "head", "options"]:
            # New-style decorator (Flask 2.0+)
            http_method = method_name.upper()
        else:
            # Old-style @app.route() - need to parse methods parameter
            http_method = self._extract_methods_from_route(decorator_node)
        
        # Extract path from decorator source code
        path = self._extract_path_from_decorator(decorator_node)
        
        return http_method, path

    def _extract_methods_from_route(self, decorator_node: GenericNode) -> str:
        """Extract HTTP methods from @app.route() decorator.
        
        Examples:
        - @app.route('/users', methods=['GET', 'POST']) -> 'GET,POST'
        - @app.route('/users') -> 'GET' (default)
        """
        if not decorator_node.source_code:
            return "GET"
        
        # Look for methods=['GET', 'POST'] pattern
        methods_match = re.search(r"methods\s*=\s*\[(.*?)\]", decorator_node.source_code, re.DOTALL)
        if methods_match:
            methods_str = methods_match.group(1)
            # Extract quoted method names
            method_names = re.findall(r"['\"](\w+)['\"]", methods_str)
            if method_names:
                return ",".join(m.upper() for m in method_names)
        
        # Default to GET if no methods specified
        return "GET"

    def _extract_path_from_decorator(self, decorator_node: GenericNode) -> Optional[str]:
        """Extract route path from decorator source code.
        
        Examples:
        - @app.route('/users') -> '/users'
        - @app.get('/users/<int:user_id>') -> '/users/<int:user_id>'
        """
        if not decorator_node.source_code:
            return None
        
        # Look for first string argument
        path_match = re.search(r"['\"]([^'\"]+)['\"]", decorator_node.source_code)
        if path_match:
            return path_match.group(1)
        
        return None

    def is_error_handler(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect Flask error handler functions.
        
        Examples:
        - @app.errorhandler(404)
        - @app.errorhandler(Exception)
        """
        from engine.models import GenericEdgeType

        decorates_edges = core_graph.get_edges_to_node(node.id)
        for edge in decorates_edges:
            if edge.edge_type != GenericEdgeType.DECORATES:
                continue

            decorator_node = core_graph.get_node(edge.source_id)
            if not decorator_node or not decorator_node.name:
                continue

            # Check for errorhandler decorator
            if "errorhandler" in decorator_node.name.lower():
                return True

        return False

    def is_hook_function(self, node: GenericNode, core_graph: CoreGraph) -> Optional[str]:
        """Detect Flask lifecycle hook functions.
        
        Returns hook type if detected, None otherwise:
        - 'before_request'
        - 'after_request'
        - 'teardown_request'
        - 'before_first_request' (deprecated)
        - 'teardown_appcontext'
        - 'context_processor'
        """
        from engine.models import GenericEdgeType

        hook_types = [
            "before_request",
            "after_request",
            "teardown_request",
            "before_first_request",
            "teardown_appcontext",
            "context_processor",
        ]

        decorates_edges = core_graph.get_edges_to_node(node.id)
        for edge in decorates_edges:
            if edge.edge_type != GenericEdgeType.DECORATES:
                continue

            decorator_node = core_graph.get_node(edge.source_id)
            if not decorator_node or not decorator_node.name:
                continue

            # Check if decorator matches any hook type
            decorator_lower = decorator_node.name.lower()
            for hook_type in hook_types:
                if hook_type in decorator_lower:
                    return hook_type

        return None
    
    # ==========================================================================
    # Application Factory Pattern Detection
    # ==========================================================================
    
    def is_application_factory(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """Detect application factory functions.
        
        Application factory pattern is a production best practice where the
        Flask app is created inside a function:
        
        def create_app(config=None):
            app = Flask(__name__)
            return app
        
        Args:
            node: Function node to check
            core_graph: Core graph for analysis
            
        Returns:
            Metadata dict if factory detected, None otherwise
        """
        if node.node_type != GenericNodeType.FUNCTION:
            return None
        
        if not node.source_code:
            return None
        
        # Check common factory names (heuristic)
        factory_names = ["create_app", "make_app", "app_factory", "create_application", "init_app"]
        if node.name in factory_names:
            # Check if function body contains Flask instantiation and return
            has_flask_instantiation = bool(re.search(r"=\s*\w*Flask\w*\s*\(", node.source_code))
            has_return = "return" in node.source_code
            if has_flask_instantiation and has_return:
                return self._extract_factory_metadata(node)
        
        # More thorough check: look for Flask instantiation + return pattern
        flask_pattern = re.search(r"(\w+)\s*=\s*\w*Flask\w*\s*\(", node.source_code)
        if flask_pattern:
            app_var = flask_pattern.group(1)
            # Check if this variable is returned
            return_pattern = rf"return\s+{app_var}\b"
            if re.search(return_pattern, node.source_code):
                return self._extract_factory_metadata(node)
        
        return None
    
    def _extract_factory_metadata(self, node: GenericNode) -> Dict[str, Any]:
        """Extract metadata from factory function."""
        metadata = {
            "app_var": None,
            "returns_app": False,
            "config_params": [],
        }
        
        if not node.source_code:
            return metadata
        
        # Extract app variable name
        flask_pattern = re.search(r"(\w+)\s*=\s*\w*Flask\w*\s*\(", node.source_code)
        if flask_pattern:
            metadata["app_var"] = flask_pattern.group(1)
            metadata["returns_app"] = bool(re.search(rf"return\s+{flask_pattern.group(1)}", node.source_code))
        
        # Extract config parameters from function signature
        sig_pattern = re.search(r"def\s+\w+\s*\(([^)]*)\)", node.source_code)
        if sig_pattern:
            params = sig_pattern.group(1)
            if params:
                metadata["config_params"] = [p.strip().split("=")[0].strip() for p in params.split(",") if p.strip()]
        
        return metadata
    
    # ==========================================================================
    # MethodView Class-Based Views Pattern Detection
    # ==========================================================================
    
    def is_methodview_class(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """Detect MethodView class-based views.
        
        MethodView is Flask's class-based view pattern:
        
        from flask.views import MethodView
        
        class UserAPI(MethodView):
            def get(self, user_id):  # HTTP GET
                pass
            def post(self):  # HTTP POST
                pass
        
        Args:
            node: Class node to check
            core_graph: Core graph for analysis
            
        Returns:
            True if class inherits from MethodView
        """
        if node.node_type != GenericNodeType.CLASS:
            return False
        
        # Check base classes in metadata
        base_classes = node.metadata.get("base_classes", [])
        
        # Must have base classes
        if not base_classes:
            return False
        
        # Direct inheritance or imported
        methodview_bases = ["MethodView", "View", "flask.views.MethodView"]
        return any(base in base_classes or base.endswith("MethodView") or base.endswith("View") 
                   for base in methodview_bases)
    
    def extract_methodview_http_methods(self, class_node: GenericNode, core_graph: CoreGraph) -> List[Dict[str, Any]]:
        """Extract HTTP methods from MethodView class.
        
        Looks for methods named after HTTP verbs.
        
        Args:
            class_node: MethodView class node
            core_graph: Core graph for looking up methods
            
        Returns:
            List of dicts with method metadata
        """
        http_verbs = {"get", "post", "put", "delete", "patch", "options", "head"}
        methods = []
        
        # Get all methods in this class
        children = core_graph.get_children(class_node.id)
        
        for child in children:
            if child.node_type == GenericNodeType.METHOD:
                method_name_lower = child.name.lower()
                if method_name_lower in http_verbs:
                    methods.append({
                        "method_name": child.name,
                        "http_verb": method_name_lower.upper(),
                        "node": child,
                        "class_name": class_node.name,
                    })
        
        return methods
    
    # ==========================================================================
    # Flask Extension Pattern Detection
    # ==========================================================================
    
    COMMON_EXTENSIONS = {
        "SQLAlchemy", "db",  # Flask-SQLAlchemy
        "Migrate", "migrate",  # Flask-Migrate
        "Mail", "mail",  # Flask-Mail
        "Login", "login_manager",  # Flask-Login
        "CORS", "cors",  # Flask-CORS
        "Cache", "cache",  # Flask-Cache
        "Limiter", "limiter",  # Flask-Limiter
        "Security", "security",  # Flask-Security
        "Admin", "admin",  # Flask-Admin
        "API", "api",  # Flask-RESTful
    }
    
    def is_extension_instantiation(self, node: GenericNode) -> Optional[str]:
        """Detect Flask extension instantiation.
        
        Args:
            node: Assignment node to check
            
        Returns:
            Extension name if detected, None otherwise
        """
        if node.node_type != GenericNodeType.ASSIGNMENT:
            return None
        
        if not node.source_code:
            return None
        
        # Pattern: db = SQLAlchemy() or similar
        match = re.search(r"=\s*(\w+)\s*\(", node.source_code)
        if not match:
            return None
        
        class_name = match.group(1)
        if class_name in self.COMMON_EXTENSIONS:
            return class_name
        
        # Heuristic: ends with common patterns
        if any(class_name.endswith(ext) for ext in ["Manager", "Handler", "Client", "Pool"]):
            return class_name
        
        return None
    
    def is_extension_initialization(self, node: GenericNode) -> Optional[Dict[str, str]]:
        """Detect extension.init_app() calls.
        
        Pattern: extension.init_app(app) or db.init_app(app)
        
        Args:
            node: Node to check
            
        Returns:
            Dict with 'extension' and 'app_var' if detected
        """
        if not node.source_code:
            return None
        
        # Pattern: extension.init_app(app)
        match = re.search(r"(\w+)\.init_app\s*\(\s*(\w+)", node.source_code)
        if match:
            return {
                "extension": match.group(1),
                "app_var": match.group(2),
            }
        
        return None
