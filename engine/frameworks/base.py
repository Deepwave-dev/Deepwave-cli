from abc import ABC, abstractmethod
from typing import Tuple, List, Optional, Set, Dict, Any
from pathlib import Path
from tree_sitter import Node as TSNode

from engine.models import CoreGraph, GenericNode, GenericNodeType, GraphNode, GraphEdge, FunctionNode
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser.query_engine import QueryEngine


class PatternMatcher(ABC):
    """
    Framework-agnostic pattern matcher.

    Detects common architectural patterns across web frameworks:
    - Application/Entry Point: Main application instance
    - Routing Configuration: Route definitions and URL patterns
    - Request Handlers: Functions/methods that handle HTTP requests
    - Dependency Injection: DI patterns and providers
    - Services/Components: Reusable business logic components
    - Middleware/Interceptors: Cross-cutting concerns
    """

    # ========== Application/Entry Point Detection ==========

    @abstractmethod
    def is_application_instance(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """
        Detect main application/entry point instance.

        Examples:
        - FastAPI: app = FastAPI()
        - Django: INSTALLED_APPS in settings.py
        - Flask: app = Flask(__name__)
        - Spring Boot: @SpringBootApplication class
        - Express: const app = express()
        - ASP.NET: Startup class or Program.cs
        """
        pass

    def get_application_imports(self) -> List[str]:
        """Return required imports/modules for application validation."""
        return []

    # ========== Routing Configuration Detection ==========

    def is_routing_configuration(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """
        Detect routing configuration (optional - not all frameworks have explicit routers).

        Examples:
        - FastAPI: router = APIRouter()
        - Django: urlpatterns in urls.py
        - Flask: blueprint = Blueprint()
        - Spring Boot: @RestController classes
        - Express: const router = express.Router()
        - ASP.NET: [Route] attributes on controllers

        Returns False by default if framework doesn't use explicit routers.
        """
        return False

    def get_routing_imports(self) -> List[str]:
        """Return required imports for routing validation."""
        return []

    # ========== Request Handler Detection ==========

    @abstractmethod
    def is_request_handler(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """
        Detect request handlers (endpoints, views, controllers).

        Returns dict with handler metadata or None if not a handler:
        {
            'http_method': 'GET' | 'POST' | 'ALL' | etc.,
            'path': '/users/{id}' or None,
            'handler_type': 'function' | 'method' | 'class',
            'decorator': decorator_node (if applicable)
        }

        Examples:
        - FastAPI: @router.get("/users") def get_users()
        - Django: def user_view(request) or class UserView(View)
        - Flask: @app.route("/users", methods=["GET"])
        - Spring Boot: @GetMapping("/users") public List<User> getUsers()
        - Express: app.get("/users", (req, res) => {})
        - ASP.NET: [HttpGet("users")] public IActionResult GetUsers()
        """
        pass

    def get_handler_imports(self) -> List[str]:
        """Return required imports for handler validation."""
        return []

    # ========== Dependency Injection Detection ==========

    def is_dependency_injection(self, node: GenericNode, core_graph: CoreGraph) -> Optional[Dict[str, Any]]:
        """
        Detect dependency injection patterns (optional - not all frameworks use DI).

        Returns dict with DI metadata or None:
        {
            'provider': provider_node,
            'consumer': consumer_node,
            'di_type': 'function' | 'constructor' | 'property' | 'attribute'
        }

        Examples:
        - FastAPI: Depends(get_db)
        - Django: Manual DI (rare)
        - Flask: Manual DI (rare)
        - Spring Boot: @Autowired, @Inject
        - Express: Middleware injection
        - ASP.NET: Constructor injection, [FromServices]
        """
        return None

    def get_dependency_imports(self) -> List[str]:
        """Return required imports for dependency validation."""
        return []

    # ========== Service/Component Detection ==========

    def is_service_component(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """
        Detect service/component classes (reusable business logic).

        Examples:
        - FastAPI: Service classes
        - Django: Service classes, managers
        - Flask: Service classes
        - Spring Boot: @Service, @Component classes
        - Express: Service modules/classes
        - ASP.NET: Service classes, repositories
        """
        return False

    def get_service_imports(self) -> List[str]:
        """Return required imports for service validation."""
        return []

    # ========== Middleware/Interceptor Detection ==========

    def is_middleware(self, node: GenericNode, core_graph: CoreGraph) -> bool:
        """
        Detect middleware/interceptor patterns (optional).

        Examples:
        - FastAPI: Middleware functions
        - Django: Middleware classes
        - Flask: @app.before_request, middleware
        - Spring Boot: @Component with HandlerInterceptor
        - Express: app.use(middleware)
        - ASP.NET: Middleware classes
        """
        return False

    # ========== Framework-Specific Helpers ==========

    @abstractmethod
    def get_framework_name(self) -> str:
        """Return framework name (e.g., 'fastapi', 'django', 'flask')."""
        pass

    @abstractmethod
    def get_language(self) -> str:
        """Return programming language (e.g., 'python', 'java', 'javascript', 'csharp')."""
        pass

    def validate_import(self, file_path: Path, symbol: str, required_modules: List[str]) -> bool:
        """
        Validate that symbol is imported from required modules.
        Framework-specific implementation.
        """
        return False


class BasePatternMatcher(PatternMatcher):
    """Base class with shared utilities for pattern matchers."""

    def __init__(self, import_graph, is_test_file_func):
        self.import_graph = import_graph
        self.is_test_file = is_test_file_func

    def _resolve_symbol(self, file_path: Path, symbol: str) -> tuple:
        """Resolve symbol through ImportGraph."""
        resolved = self.import_graph.resolve_name(file_path, symbol)
        return resolved if resolved else (None, None)

    def _is_string_literal_assignment(self, source_code: str) -> bool:
        """Check if assignment is to a string literal."""
        if not source_code or "=" not in source_code:
            return False
        rhs = source_code.split("=", 1)[1].strip()
        return any(rhs.startswith(delim) for delim in ['"""', "'''", '"', "'"])

    def validate_import(self, file_path: Path, symbol: str, required_modules: List[str]) -> bool:
        """Validate that symbol is imported from required modules."""
        resolved = self.import_graph.resolve_name(file_path, symbol)
        if not resolved:
            return False
        module, _ = resolved
        return module and any(req in module for req in required_modules)


class NodeMapper(ABC):
    """
    Framework-agnostic interface for mapping generic nodes to domain-specific nodes.

    Aligns with PatternMatcher terminology for consistency:
    - map_entry_point: Maps application/entry point instances (FastAPI app, Flask app, Django INSTALLED_APPS, etc.)
    - map_routing_config: Maps routing configurations (APIRouter, Blueprint, URLConf, Express Router, etc.)
    - map_request_handler: Maps request handlers (endpoints, views, controller methods, route handlers, etc.)
    """

    @abstractmethod
    def map_entry_point(self, generic_node: GenericNode, project_hash: str, project_path: Path) -> GraphNode:
        """
        Map entry point/application node to domain node.

        Examples:
        - FastAPI: app = FastAPI() -> ApplicationNode
        - Flask: app = Flask(__name__) -> ApplicationNode
        - Django: INSTALLED_APPS in settings.py -> ApplicationNode
        - Spring Boot: @SpringBootApplication class -> ApplicationNode
        - Express: const app = express() -> ApplicationNode
        """
        pass

    @abstractmethod
    def map_routing_config(self, generic_node: GenericNode, project_hash: str, project_path: Path) -> GraphNode:
        """
        Map routing configuration node to domain node.

        Examples:
        - FastAPI: router = APIRouter() -> RouterNode
        - Flask: blueprint = Blueprint() -> RouterNode
        - Django: urlpatterns in urls.py -> RouterNode
        - Express: const router = express.Router() -> RouterNode
        """
        pass

    @abstractmethod
    def map_request_handler(
        self, func_node: GenericNode, decorator_node: Optional[GenericNode], project_hash: str, project_path: Path
    ) -> GraphNode:
        """
        Map request handler to domain node.

        Examples:
        - FastAPI: @router.get("/users") def get_users() -> EndpointNode
        - Django: def user_view(request) or class UserView(View) -> EndpointNode
        - Flask: @app.route("/users", methods=["GET"]) -> EndpointNode
        - Spring Boot: @GetMapping("/users") public List<User> getUsers() -> EndpointNode
        - Express: app.get("/users", (req, res) => {}) -> EndpointNode
        """
        pass


class FrameworkFilter(ABC):
    """Interface for framework-specific filtering of the CoreGraph."""

    services: List[GenericNode]

    @abstractmethod
    def filter(self, core_graph: CoreGraph) -> None:
        """Analyze core graph to identify framework patterns."""
        pass

    def _find_and_validate(
        self,
        core_graph: CoreGraph,
        node_type: GenericNodeType,
        pattern_check: callable,
        import_getter: callable,
        storage_list: List[GenericNode],
    ) -> None:
        """Generic helper: find nodes, filter by pattern, validate imports."""
        nodes = core_graph.get_nodes_by_type(node_type)
        candidates = [n for n in nodes if pattern_check(n, core_graph)]
        validated = [n for n in candidates if self._validate_import(n, core_graph, import_getter())]
        storage_list[:] = validated

    def _validate_import(self, node: GenericNode, core_graph: CoreGraph, required_imports: List[str]) -> bool:
        """Validate required imports using semantic resolution."""
        # This should be implemented by subclasses that have access to import_graph
        # For now, return True to allow frameworks without import validation
        return True


class DependencyResolver(ABC):
    """Base class for framework-specific dependency injection resolution."""

    @abstractmethod
    def resolve_dependency_chain(
        self, provider_node: FunctionNode, depth: int = 0, max_depth: int = 10, visited: Optional[Set[str]] = None
    ) -> List[FunctionNode]:
        """Recursively resolve the complete dependency chain starting from a provider function."""
        pass

    @abstractmethod
    def extract_provider_from_node(self, node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """Extract provider function from framework-specific dependency node."""
        pass


class EdgeDiscoverer(ABC):
    """Base class for framework-specific edge discovery."""

    @abstractmethod
    def discover(self) -> List[GraphEdge]:
        """Discover framework-specific edges (includes, routes, etc.)."""
        pass


class DomainMapper(ABC):
    """Interface for mapping generic nodes to domain-specific nodes."""

    @abstractmethod
    def map(self) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Map generic nodes to domain nodes and edges."""
        pass
