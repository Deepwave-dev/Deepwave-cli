"""Flask Filter - Identifies Flask-specific patterns in CoreGraph.

This filter analyzes the language-agnostic CoreGraph to identify Flask-specific patterns
such as applications, blueprints, endpoints, services, and hooks.
"""

from pathlib import Path
from typing import List, Tuple, Optional
from tree_sitter import Node as TSNode

from engine.models import CoreGraph, GenericNode, GenericNodeType, GenericEdgeType
from engine.frameworks.base import FrameworkFilter
from engine.frameworks.flask.pattern_matcher import FlaskPatternMatcher
from engine.frameworks.flask.query_cache import QueryResultCache
from engine.parser import QueryEngine
from engine.parser.parse_cache import ParseCache
from engine.ignore import is_test_file


class FlaskFilter(FrameworkFilter):
    """Identifies Flask-specific patterns in a CoreGraph.
    
    Extracts:
    - Flask() application instances
    - Blueprint() instances
    - Route endpoints (@app.route, @bp.route, @app.get, etc.)
    - Error handlers (@app.errorhandler)
    - Lifecycle hooks (@app.before_request, etc.)
    - Service classes
    - Methods and functions
    """

    def __init__(self, project_hash: str, project_path: Path, parse_cache: ParseCache, import_graph):
        """Initialize the Flask filter.
        
        Args:
            project_hash: Project hash for ID generation
            project_path: Project root path
            parse_cache: ParseCache for file parsing
            import_graph: ImportGraph for symbol resolution
        """
        self.project_hash = project_hash
        self.project_path = project_path
        self.parse_cache = parse_cache
        self.import_graph = import_graph
        self.parser = parse_cache.parser
        self.query_engine = QueryEngine(self.parser, query_subdirectory="flask")
        self.pattern_matcher = FlaskPatternMatcher(import_graph, is_test_file)
        self.query_cache = QueryResultCache()  # Performance optimization

        # Storage for identified patterns (GenericNodes)
        self.applications: List[GenericNode] = []
        self.blueprints: List[GenericNode] = []
        self.endpoints: List[Tuple[GenericNode, GenericNode]] = []  # (function, decorator)
        self.error_handlers: List[Tuple[GenericNode, GenericNode]] = []  # (function, decorator)
        self.hooks: List[Tuple[GenericNode, GenericNode, str]] = []  # (function, decorator, hook_type)
        self.services: List[GenericNode] = []
        self.methods: List[GenericNode] = []
        self.functions: List[GenericNode] = []
        self.entry_points: List[GenericNode] = []
        
        # Extended patterns
        self.factory_functions: List[Tuple[GenericNode, dict]] = []  # (function, metadata)
        self.methodview_classes: List[Tuple[GenericNode, List[dict]]] = []  # (class, http_methods)
        self.extensions: List[GenericNode] = []  # Extension instantiations
        self.extension_initializations: List[Tuple[GenericNode, dict]] = []  # (node, init_data)

    def filter(self, core_graph: CoreGraph) -> None:
        """Analyze the CoreGraph to identify Flask-specific patterns.
        
        Args:
            core_graph: The language-agnostic CoreGraph to analyze
        """
        # Find Flask patterns in dependency order
        self._find_applications(core_graph)
        self._find_blueprints(core_graph)
        self._find_endpoints(core_graph)
        self._find_error_handlers(core_graph)
        self._find_hooks(core_graph)
        self._find_services(core_graph)
        self._find_methods(core_graph)
        self._find_functions(core_graph)
        self._find_entry_points(core_graph)
        
        # Find extended patterns
        self._find_factory_functions(core_graph)
        self._find_methodview_classes(core_graph)
        self._find_extensions(core_graph)

    def _find_applications(self, core_graph: CoreGraph) -> None:
        """Find Flask application instantiations.
        
        Pattern: app = Flask(__name__)
        """
        self._find_and_validate(
            core_graph,
            GenericNodeType.ASSIGNMENT,
            self.pattern_matcher.is_application_instance,
            self.pattern_matcher.get_application_imports,
            self.applications,
        )

    def _find_blueprints(self, core_graph: CoreGraph) -> None:
        """Find Blueprint instantiations.
        
        Pattern: bp = Blueprint('name', __name__)
        """
        self._find_and_validate(
            core_graph,
            GenericNodeType.ASSIGNMENT,
            self.pattern_matcher.is_routing_configuration,
            self.pattern_matcher.get_routing_imports,
            self.blueprints,
        )

    def _find_endpoints(self, core_graph: CoreGraph) -> None:
        """Find Flask endpoint functions in the CoreGraph.
        
        Patterns:
        - @app.route('/users', methods=['GET', 'POST'])
        - @app.get('/users')
        - @bp.post('/users')
        """
        functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)

        for func_node in functions:
            # Find DECORATES edges pointing to this function
            decorates_edges = core_graph.get_edges_to_node(func_node.id)

            for edge in decorates_edges:
                if edge.edge_type != GenericEdgeType.DECORATES:
                    continue

                decorator_node = core_graph.get_node(edge.source_id)
                if not decorator_node:
                    continue

                # Check if this is a request handler
                handler_info = self.pattern_matcher.is_request_handler(func_node, core_graph)
                if handler_info:
                    self.endpoints.append((func_node, decorator_node))
                    break  # Only count each function once

    def _find_error_handlers(self, core_graph: CoreGraph) -> None:
        """Find Flask error handler functions.
        
        Pattern: @app.errorhandler(404)
        """
        functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)

        for func_node in functions:
            if self.pattern_matcher.is_error_handler(func_node, core_graph):
                # Find the errorhandler decorator
                decorates_edges = core_graph.get_edges_to_node(func_node.id)
                for edge in decorates_edges:
                    if edge.edge_type != GenericEdgeType.DECORATES:
                        continue
                    decorator_node = core_graph.get_node(edge.source_id)
                    if decorator_node and "errorhandler" in decorator_node.name.lower():
                        self.error_handlers.append((func_node, decorator_node))
                        break

    def _find_hooks(self, core_graph: CoreGraph) -> None:
        """Find Flask lifecycle hook functions.
        
        Patterns:
        - @app.before_request
        - @app.after_request
        - @app.teardown_request
        """
        functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)

        for func_node in functions:
            hook_type = self.pattern_matcher.is_hook_function(func_node, core_graph)
            if hook_type:
                # Find the hook decorator
                decorates_edges = core_graph.get_edges_to_node(func_node.id)
                for edge in decorates_edges:
                    if edge.edge_type != GenericEdgeType.DECORATES:
                        continue
                    decorator_node = core_graph.get_node(edge.source_id)
                    if decorator_node and hook_type in decorator_node.name.lower():
                        self.hooks.append((func_node, decorator_node, hook_type))
                        break

    def _find_services(self, core_graph: CoreGraph) -> None:
        """Find service classes in the CoreGraph.
        
        Uses same heuristics as FastAPI:
        - Classes with instance methods
        - Excluding Pydantic models, dataclasses, ABCs
        """
        classes = core_graph.get_nodes_by_type(GenericNodeType.CLASS)

        for class_node in classes:
            if self._is_service_class(class_node, core_graph):
                self.services.append(class_node)

    def _find_methods(self, core_graph: CoreGraph) -> None:
        """Find methods belonging to service classes.
        
        Pattern: methods (functions inside classes) that belong to identified services
        """
        for service_node in self.services:
            # Get children of this service class
            children = core_graph.get_children(service_node.id)

            for child in children:
                if child.node_type == GenericNodeType.METHOD:
                    self.methods.append(child)

    def _find_functions(self, core_graph: CoreGraph) -> None:
        """Find all standalone functions in the CoreGraph.
        
        Note: Methods are tracked separately in self.methods.
        """
        standalone_functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)
        self.functions = list(standalone_functions)

    def _find_entry_points(self, core_graph: CoreGraph) -> None:
        """Find entry point functions that instantiate services.
        
        Excludes:
        - Endpoints
        - Test files
        - Functions that are called by others
        """
        endpoint_function_ids = {func_node.id for func_node, _ in self.endpoints}
        calls_edges = core_graph.get_edges_by_type(GenericEdgeType.CALLS)
        called_function_ids = {edge.target_id for edge in calls_edges}

        candidate_entry_points = []
        for func in self.functions:
            if func.node_type == GenericNodeType.METHOD:
                continue
            if self._is_test_file(func.file_path):
                continue
            if func.id in endpoint_function_ids:
                continue
            if func.id not in called_function_ids:
                candidate_entry_points.append(func)

        for candidate in candidate_entry_points:
            if self._instantiates_service(candidate, core_graph):
                self.entry_points.append(candidate)

    # Helper methods for service detection (reused from FastAPI)

    def _is_service_class(self, class_node: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if class is a service.
        
        Includes infrastructure classes, excludes model classes.
        Uses same heuristics as FastAPI.
        """
        # Exclude model classes: Pydantic models, dataclasses, or classes with 0 methods
        if self._is_pydantic_model(class_node) or self._is_dataclass(class_node, core_graph):
            return False

        # Exclude abstract base classes (ABC)
        if self._is_abstract_base_class(class_node):
            return False

        children = core_graph.get_children(class_node.id)
        methods = [c for c in children if c.node_type == GenericNodeType.METHOD]

        # Exclude classes with no instance methods (only static/abstract methods)
        if not methods or self._has_only_static_methods(class_node, methods, core_graph):
            return False

        # Include any class with instance methods
        return True

    def _is_abstract_base_class(self, class_node: GenericNode) -> bool:
        """Check if class is an abstract base class (inherits from ABC)."""
        if not class_node.source_code:
            return False

        # Check first line for ABC inheritance
        lines = class_node.source_code.split("\n")
        first_line = lines[0] if lines else class_node.source_code

        return "(ABC)" in first_line or ", ABC)" in first_line or "ABC," in first_line

    def _has_only_static_methods(
        self, class_node: GenericNode, methods: List[GenericNode], core_graph: CoreGraph
    ) -> bool:
        """Check if class has only static methods (no instance methods)."""
        if not methods:
            return True

        # Check if all methods are static or abstract
        file_nodes = core_graph.get_nodes_by_file(class_node.file_path)
        decorators = {n.start_line: n for n in file_nodes if n.node_type == GenericNodeType.DECORATOR}

        instance_method_count = 0
        for method in methods:
            # Check if method has @staticmethod or @abstractmethod decorator
            is_static = False
            is_abstract = False

            # Check decorators near this method
            for line_num, decorator in decorators.items():
                if abs(line_num - method.start_line) <= 2:
                    decorator_name = decorator.name or ""
                    if "staticmethod" in decorator_name.lower():
                        is_static = True
                    if "abstractmethod" in decorator_name.lower():
                        is_abstract = True

            # If method is not static and not abstract, it's an instance method
            if not is_static and not is_abstract:
                instance_method_count += 1

        # If no instance methods, exclude this class
        return instance_method_count == 0

    def _is_pydantic_model(self, class_node: GenericNode) -> bool:
        """Check if class inherits from Pydantic BaseModel."""
        if not class_node.source_code:
            return False

        # Only check the first line (class definition line)
        lines = class_node.source_code.split("\n")
        first_line = lines[0] if lines else class_node.source_code

        pydantic_patterns = ["(BaseModel)", "(BaseModel,", ", BaseModel)", ", BaseModel,", "pydantic.BaseModel"]
        return any(pattern in first_line for pattern in pydantic_patterns)

    def _is_dataclass(self, class_node: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if class is decorated with @dataclass."""
        try:
            # Read the file to check for @dataclass decorator before the class
            if not class_node.file_path.exists():
                return False

            with open(class_node.file_path, "r", encoding="utf-8") as f:
                file_lines = f.readlines()

            # Check lines before the class definition (decorator is typically 1-2 lines before)
            start_line = class_node.start_line - 1  # Convert to 0-indexed
            for i in range(max(0, start_line - 3), start_line + 1):
                if i < len(file_lines) and "@dataclass" in file_lines[i].lower():
                    return True
        except Exception:
            pass

        # Fallback: check source_code if available
        if class_node.source_code:
            lines = class_node.source_code.split("\n")
            for line in lines[:5]:
                if "@dataclass" in line.lower():
                    return True

        # Also check file nodes for decorator nodes (fallback)
        file_nodes = core_graph.get_nodes_by_file(class_node.file_path)
        decorators = [n for n in file_nodes if n.node_type == GenericNodeType.DECORATOR]
        for decorator in decorators:
            if "dataclass" in (decorator.name or "").lower() and abs(decorator.start_line - class_node.start_line) <= 2:
                return True
        return False

    def _instantiates_service(self, func: GenericNode, core_graph: CoreGraph) -> bool:
        """Check if function instantiates any service."""
        if not func.source_code:
            return False
        return any(f"{service.name}(" in func.source_code for service in self.services)

    def _is_test_file(self, file_path: Path) -> bool:
        """Check if file is a test file."""
        return is_test_file(file_path)

    def _validate_import(self, node: GenericNode, core_graph: CoreGraph, required_imports: List[str]) -> bool:
        """Validate required imports using semantic resolution."""
        for required in required_imports:
            resolved = self.import_graph.resolve_name(node.file_path, required)
            if resolved and resolved[0]:
                return True
        return False
    
    # ============================================================================
    # Extended Pattern Detection
    # ============================================================================
    
    def _find_factory_functions(self, core_graph: CoreGraph) -> None:
        """Find application factory functions.
        
        Pattern: def create_app(): return Flask()
        """
        functions = core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)
        
        for func_node in functions:
            if self._is_test_file(func_node.file_path):
                continue
            
            factory_metadata = self.pattern_matcher.is_application_factory(func_node, core_graph)
            if factory_metadata:
                self.factory_functions.append((func_node, factory_metadata))
                # Also add to entry_points for backwards compatibility
                if func_node not in self.entry_points:
                    self.entry_points.append(func_node)
    
    def _find_methodview_classes(self, core_graph: CoreGraph) -> None:
        """Find MethodView class-based views.
        
        Pattern: class UserAPI(MethodView): def get(self): ...
        """
        classes = core_graph.get_nodes_by_type(GenericNodeType.CLASS)
        
        for class_node in classes:
            if self._is_test_file(class_node.file_path):
                continue
            
            if self.pattern_matcher.is_methodview_class(class_node, core_graph):
                http_methods = self.pattern_matcher.extract_methodview_http_methods(class_node, core_graph)
                if http_methods:
                    self.methodview_classes.append((class_node, http_methods))
    
    def _find_extensions(self, core_graph: CoreGraph) -> None:
        """Find Flask extension instantiations and initializations.
        
        Patterns:
        - db = SQLAlchemy()
        - db.init_app(app)
        """
        assignments = core_graph.get_nodes_by_type(GenericNodeType.ASSIGNMENT)
        
        for node in assignments:
            if self._is_test_file(node.file_path):
                continue
            
            # Check for extension instantiation
            extension_name = self.pattern_matcher.is_extension_instantiation(node)
            if extension_name:
                self.extensions.append(node)
            
            # Check for init_app() calls
            init_data = self.pattern_matcher.is_extension_initialization(node)
            if init_data:
                self.extension_initializations.append((node, init_data))
