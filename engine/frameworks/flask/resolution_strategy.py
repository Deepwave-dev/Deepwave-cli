"""Flask-specific resolution strategy for symbol resolution.

This module provides Flask-specific logic for resolving symbols (apps, blueprints, services)
during code analysis. It extends the base ResolutionStrategy to handle Flask's unique patterns.
"""

from typing import Optional, List

from engine.binder.resolution_strategy import ResolutionStrategy
from engine.binder import SymbolIndex
from engine.models import BaseNode, NodeType


class FlaskResolutionStrategy(ResolutionStrategy):
    """Flask-specific resolution strategy for apps, blueprints, and services.
    
    This strategy handles resolution of Flask-specific components:
    - Flask application instances (app = Flask(__name__))
    - Blueprint instances (bp = Blueprint('name', __name__))
    - Service classes and instances
    
    The resolution follows a hierarchy:
    1. Local instances in the same file
    2. Imported instances from other modules
    3. Service classes project-wide
    """

    def get_resolution_types(self) -> List[NodeType]:
        """Return Flask node types: application, router (blueprint), service_class.
        
        Returns:
            List of NodeType that Flask can resolve:
            - NodeType.application: Flask app instances
            - NodeType.router: Blueprint instances (Flask uses "router" internally for blueprints)
            - NodeType.service_class: Service classes
        """
        return [NodeType.application, NodeType.router, NodeType.service_class]

    def find_local_instances(self, symbol_index: SymbolIndex, file_rel: str, identifier: str) -> Optional[BaseNode]:
        """Find local Flask instances in the same file.
        
        Searches for Flask components (app, blueprint, service) in the same file
        where the identifier is referenced. This is the first resolution strategy.
        
        Args:
            symbol_index: The symbol index to search
            file_rel: Relative path to the file (e.g., 'app/routes/users.py')
            identifier: The identifier to find (e.g., 'app', 'users_bp', 'UserService')
            
        Returns:
            BaseNode if found, None otherwise
            
        Example:
            # In routes/users.py
            app = Flask(__name__)
            @app.route('/users')  # <- find 'app' resolves to Flask instance
        """
        return (
            symbol_index.find_app(file_rel, identifier)
            or symbol_index.find_router(file_rel, identifier)
            or symbol_index.find_service_instance(file_rel, identifier)
        )

    def find_by_module(self, symbol_index: SymbolIndex, module_path: str, identifier: str) -> Optional[BaseNode]:
        """Find Flask component by module path.
        
        Used when an identifier is imported from another module. Searches for
        Flask apps or blueprints by their module path and identifier.
        
        Args:
            symbol_index: The symbol index to search
            module_path: Module path (e.g., 'app.main', 'app.routes.users')
            identifier: The identifier to find (e.g., 'app', 'users_bp')
            
        Returns:
            BaseNode if found, None otherwise
            
        Example:
            # In routes/users.py
            from app import app  # <- find by module 'app' and identifier 'app'
            @app.route('/users')
        """
        return (
            symbol_index.find_app_by_module(module_path, identifier)
            or symbol_index.find_router_by_module(module_path, identifier)
        )

    def find_by_file(self, symbol_index: SymbolIndex, file_rel: str, identifier: str) -> Optional[BaseNode]:
        """Find Flask component by file path.
        
        Fallback strategy that searches for Flask components (app, blueprint, service)
        in a specific file. Also includes project-wide service class search.
        
        Args:
            symbol_index: The symbol index to search
            file_rel: Relative path to the file
            identifier: The identifier to find
            
        Returns:
            BaseNode if found, None otherwise
            
        Example:
            # When resolving a variable in any file
            # Search in the same file first, then project-wide for services
        """
        return (
            symbol_index.find_app(file_rel, identifier)
            or symbol_index.find_router(file_rel, identifier)
            or symbol_index.find_service_instance(file_rel, identifier)
            or symbol_index.find_service_class(identifier)
        )

    def find_attribute_by_module(
        self, symbol_index: SymbolIndex, module_path: str, attribute_name: str
    ) -> Optional[BaseNode]:
        """Find Flask component by module path for attribute access.
        
        Used when resolving attribute access on imported identifiers.
        
        Args:
            symbol_index: The symbol index to search
            module_path: Module path (e.g., 'app.routes.users')
            attribute_name: The attribute name (e.g., 'route', 'before_request')
            
        Returns:
            BaseNode if found, None otherwise
            
        Example:
            # In routes/users.py
            from app.blueprints import users_bp
            @users_bp.route('/profile')  # <- find 'users_bp' by module
        """
        return (
            symbol_index.find_router_by_module(module_path, attribute_name)
            or symbol_index.find_app_by_module(module_path, attribute_name)
        )

    def find_attribute_by_file(
        self, symbol_index: SymbolIndex, file_rel: str, attribute_name: str
    ) -> Optional[BaseNode]:
        """Find Flask component by file path for attribute access.
        
        Used when resolving attribute access on local identifiers.
        
        Args:
            symbol_index: The symbol index to search
            file_rel: Relative path to the file
            attribute_name: The attribute name
            
        Returns:
            BaseNode if found, None otherwise
            
        Example:
            # In routes/users.py
            app = Flask(__name__)
            @app.route('/users')  # <- find 'app' attribute access
        """
        return (
            symbol_index.find_router(file_rel, attribute_name)
            or symbol_index.find_app(file_rel, attribute_name)
            or symbol_index.find_service_instance(file_rel, attribute_name)
        )
