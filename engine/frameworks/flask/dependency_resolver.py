"""Flask Dependency Resolver - Resolves manual dependency injection patterns in Flask.

Flask doesn't have built-in dependency injection like FastAPI's Depends(), but uses
manual DI patterns such as:
- Service instantiation in application factory
- Services passed as function parameters
- Request context dependencies (g object)
- Blueprint-level service injection

This resolver identifies and traces these manual DI patterns.
"""

from pathlib import Path
from typing import List, Set, Optional, Dict
from tree_sitter import Node as TSNode

from engine.models import ExpressionType, FunctionNode
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser import QueryEngine
from engine.ignore import file_to_module_path
from engine.frameworks.base import DependencyResolver as BaseDependencyResolver


class FlaskDependencyResolver(BaseDependencyResolver):
    """Resolves Flask manual dependency injection patterns.
    
    Unlike FastAPI which has explicit Depends() markers, Flask uses manual DI patterns
    that we need to infer from the code structure:
    
    1. **Function Parameters**: Services passed as function arguments
       ```python
       def get_user(user_service: UserService):
           return user_service.find_user()
       ```
    
    2. **Service Instantiation**: Direct instantiation of service classes
       ```python
       user_service = UserService()
       ```
    
    3. **Application Factory**: Services created in create_app()
       ```python
       def create_app():
           db = Database()
           return app
       ```
    """

    def __init__(self, binder: SymbolResolver, query_engine: QueryEngine, project_hash: Optional[str] = None):
        """Initialize the Flask dependency resolver.
        
        Args:
            binder: SymbolResolver instance for symbol resolution
            query_engine: QueryEngine configured for Flask queries
            project_hash: Project hash for creating FunctionNode IDs
        """
        self.binder = binder
        self.query_engine = query_engine
        self.parser = query_engine.parser
        # Create a separate query engine for generic queries (finding functions)
        self.generic_query_engine = QueryEngine(self.parser, query_subdirectory="generic")
        self.project_hash = project_hash or "default"

        # Cache to avoid infinite loops and redundant work
        self._dependency_cache: Dict[str, List[FunctionNode]] = {}
        # Cache for function lookups to avoid repeated project-wide searches
        self._function_lookup_cache: Dict[str, Optional[FunctionNode]] = {}

    def resolve_dependency_chain(
        self, provider_node: FunctionNode, depth: int = 0, max_depth: int = 10, visited: Optional[Set[str]] = None
    ) -> List[FunctionNode]:
        """Recursively resolve the dependency chain for a Flask function.
        
        Flask manual DI patterns we detect:
        1. Function parameters that are service classes
        2. Service instantiation within the function body
        3. Function calls that return services
        
        Args:
            provider_node: The function to analyze for dependencies
            depth: Current recursion depth
            max_depth: Maximum recursion depth to prevent infinite loops
            visited: Set of already visited function IDs to detect circular dependencies
            
        Returns:
            List of FunctionNode representing the dependency chain
            
        Example:
            ```python
            def get_user_data(db: Database):  # <- db is a dependency
                user_service = UserService(db)  # <- UserService is a dependency
                return user_service.get_user()
            ```
        """
        if visited is None:
            visited = set()

        if depth >= max_depth or provider_node.id in visited:
            return []

        # Check cache
        if provider_node.id in self._dependency_cache:
            return self._dependency_cache[provider_node.id]

        # Mark as visited
        visited.add(provider_node.id)

        # Result accumulator
        dependencies: List[FunctionNode] = []

        # Parse the provider function to find dependencies
        file_path = Path(provider_node.path)
        if not file_path.is_absolute():
            file_path = self.binder.project_path / file_path

        if not file_path.exists():
            return []

        tree = self.parser.parse_file(file_path)
        if not tree:
            return []

        try:
            # Strategy 1: Find service instantiation patterns in function body
            # Pattern: ServiceClass() or ServiceClass(args)
            dependencies_from_calls = self._find_service_instantiations(
                tree, provider_node, file_path
            )
            dependencies.extend(dependencies_from_calls)
            
            # Strategy 2: Find function parameters that are services
            # Pattern: def func(service: ServiceClass):
            dependencies_from_params = self._find_service_parameters(
                tree, provider_node, file_path
            )
            dependencies.extend(dependencies_from_params)
            
            # Recursively resolve nested dependencies
            for dep in list(dependencies):  # Create a copy to avoid modification during iteration
                nested_deps = self.resolve_dependency_chain(dep, depth + 1, max_depth, visited.copy())
                dependencies.extend(nested_deps)

        except Exception:
            # Silently continue if dependency resolution fails
            pass

        # Cache the result
        self._dependency_cache[provider_node.id] = dependencies

        return dependencies

    def extract_provider_from_node(self, node: TSNode, file_path: Path) -> Optional[FunctionNode]:
        """Extract provider function from a service instantiation or function call.
        
        For Flask, this looks for:
        - Service class instantiation: UserService()
        - Factory function calls: create_service()
        
        Args:
            node: Tree-sitter node representing the call
            file_path: Path to the file containing the node
            
        Returns:
            FunctionNode if a provider function is found, None otherwise
        """
        # Handle direct identifiers (service class names)
        if node.type == ExpressionType.IDENTIFIER:
            class_name = node.text.decode("utf-8", errors="ignore")
            return self._find_class_init(class_name, file_path)
        
        # Handle call expressions (service instantiation)
        if node.type == ExpressionType.CALL:
            function_node = node.child_by_field_name("function")
            if function_node:
                if function_node.type == ExpressionType.IDENTIFIER:
                    func_name = function_node.text.decode("utf-8", errors="ignore")
                    # Check if it's a service class (capitalized) or factory function
                    if func_name[0].isupper():
                        # Likely a class instantiation
                        return self._find_class_init(func_name, file_path)
                    else:
                        # Likely a factory function
                        return self._find_function_in_file(file_path, func_name)
        
        return None

    def _find_service_instantiations(
        self, tree, provider_node: FunctionNode, file_path: Path
    ) -> List[FunctionNode]:
        """Find service instantiation patterns within a function body.
        
        Looks for patterns like:
        - service = ServiceClass()
        - service = ServiceClass(args)
        - ServiceClass().method()
        
        Args:
            tree: Parsed tree-sitter tree
            provider_node: The function to analyze
            file_path: Path to the file
            
        Returns:
            List of FunctionNode representing instantiated services
        """
        dependencies = []
        
        # Find the function node in the tree
        func_node = self._find_function_node_in_tree(tree, provider_node)
        if not func_node:
            return dependencies
        
        # Find body node
        body_node = func_node.child_by_field_name("body")
        if not body_node:
            return dependencies
        
        # Find all call nodes in the body
        call_nodes = self._find_calls(body_node)
        
        for call_node in call_nodes:
            func_attr = call_node.child_by_field_name("function")
            if not func_attr:
                continue
            
            # Check for direct class instantiation: ServiceClass()
            if func_attr.type == ExpressionType.IDENTIFIER:
                class_name = func_attr.text.decode("utf-8", errors="ignore")
                # Heuristic: Class names typically start with uppercase
                if class_name[0].isupper():
                    init_func = self._find_class_init(class_name, file_path)
                    if init_func:
                        dependencies.append(init_func)
        
        return dependencies

    def _find_service_parameters(
        self, tree, provider_node: FunctionNode, file_path: Path
    ) -> List[FunctionNode]:
        """Find service classes passed as function parameters.
        
        Looks for patterns like:
        - def func(service: ServiceClass):
        - def func(db: Database, cache: Cache):
        
        Args:
            tree: Parsed tree-sitter tree
            provider_node: The function to analyze
            file_path: Path to the file
            
        Returns:
            List of FunctionNode representing service parameters
        """
        dependencies = []
        
        # Find the function node in the tree
        func_node = self._find_function_node_in_tree(tree, provider_node)
        if not func_node:
            return dependencies
        
        # Find parameters node
        params_node = func_node.child_by_field_name("parameters")
        if not params_node:
            return dependencies
        
        # Iterate through parameters looking for type annotations
        for child in params_node.children:
            if child.type == "typed_parameter":
                # Get the type annotation
                type_node = child.child_by_field_name("type")
                if type_node and type_node.type == ExpressionType.IDENTIFIER:
                    type_name = type_node.text.decode("utf-8", errors="ignore")
                    # Heuristic: Service classes typically start with uppercase
                    if type_name[0].isupper():
                        init_func = self._find_class_init(type_name, file_path)
                        if init_func:
                            dependencies.append(init_func)
        
        return dependencies

    def _find_function_node_in_tree(self, tree, func_generic_node: FunctionNode) -> Optional[TSNode]:
        """Find the tree-sitter function node matching a FunctionNode."""
        func_line = func_generic_node.start_line
        
        def find_function_node(node: TSNode, target_line: int) -> Optional[TSNode]:
            if node.type in ["function_definition", "decorated_definition"]:
                if node.start_point[0] + 1 == target_line or (
                    node.type == "decorated_definition"
                    and any(child.start_point[0] + 1 == target_line for child in node.children)
                ):
                    if node.type == "decorated_definition":
                        # Get the actual function_definition
                        for child in node.children:
                            if child.type == "function_definition":
                                return child
                    return node

            for child in node.children:
                result = find_function_node(child, target_line)
                if result:
                    return result
            return None

        return find_function_node(tree.root_node, func_line)

    def _find_calls(self, node: TSNode) -> List[TSNode]:
        """Recursively find all call nodes in a tree."""
        calls = []
        if node.type == ExpressionType.CALL:
            calls.append(node)
        for child in node.children:
            calls.extend(self._find_calls(child))
        return calls

    def _find_class_init(self, class_name: str, file_path: Path) -> Optional[FunctionNode]:
        """Find the __init__ method of a class for class-based dependencies.
        
        Args:
            class_name: Name of the class
            file_path: Path to start searching from
            
        Returns:
            FunctionNode representing the __init__ method, or None
        """
        # First, try to resolve the class through imports
        resolved = self.binder.import_graph.resolve_name(file_path, class_name)
        if resolved:
            source_module, _ = resolved
            source_file = self.binder.import_graph.file_for_module(source_module)
            if source_file:
                return self._search_class_init_in_file(source_file, class_name)
        
        # Search in current file
        init_func = self._search_class_init_in_file(file_path, class_name)
        if init_func:
            return init_func
        
        # Search project-wide as last resort
        from engine.ignore import discover_python_files
        
        python_files = discover_python_files(self.binder.project_path)
        for py_file in python_files:
            if py_file == file_path:
                continue
            init_func = self._search_class_init_in_file(py_file, class_name)
            if init_func:
                return init_func
        
        return None

    def _search_class_init_in_file(self, file_path: Path, class_name: str) -> Optional[FunctionNode]:
        """Search for a class's __init__ method in a specific file."""
        if not file_path.exists():
            return None

        tree = self.parser.parse_file(file_path)
        if not tree:
            return None

        # First, find the class
        class_query = """
        (class_definition
          name: (identifier) @class_name
          body: (block) @class_body
        ) @class_def
        """
        results = self.query_engine.execute_query_string(tree, class_query, "class_definitions")
        
        for result in results:
            found_class_name = result.captures.get("class_name")
            if found_class_name and found_class_name.text.decode() == class_name:
                class_body = result.captures.get("class_body")
                if not class_body:
                    continue
                
                # Find __init__ within the class body
                for child in class_body.children:
                    if child.type == "function_definition":
                        name_node = child.child_by_field_name("name")
                        if name_node and name_node.text.decode() == "__init__":
                            module_name = file_to_module_path(file_path, self.binder.project_path)
                            return FunctionNode.from_tree_sitter(
                                node=child,
                                file_path=file_path,
                                project_path=self.binder.project_path,
                                project_hash=self.project_hash,
                                module_name=module_name,
                                parent_class=class_name,
                            )

        return None

    def _find_function_in_file(self, file_path: Path, function_name: str) -> Optional[FunctionNode]:
        """Find a function by name, searching in imported modules, current file, or project-wide.
        
        Args:
            file_path: Path to start searching from
            function_name: Name of the function to find
            
        Returns:
            FunctionNode if found, None otherwise
        """
        # Check cache first
        cache_key = f"{file_path}:{function_name}"
        if cache_key in self._function_lookup_cache:
            return self._function_lookup_cache[cache_key]

        # Strategy 1: Check if function is imported, then search in source file
        resolved = self.binder.import_graph.resolve_name(file_path, function_name)
        if resolved:
            source_module, source_symbol = resolved
            lookup_name = source_symbol if source_symbol else function_name
            source_file = self.binder.import_graph.file_for_module(source_module)
            if source_file:
                func_node = self._search_function_in_file(source_file, lookup_name)
                if func_node:
                    self._function_lookup_cache[cache_key] = func_node
                    return func_node

        # Strategy 2: Search in current file
        func_node = self._search_function_in_file(file_path, function_name)
        if func_node:
            self._function_lookup_cache[cache_key] = func_node
            return func_node

        # Strategy 3: Search project-wide (last resort)
        from engine.ignore import discover_python_files

        python_files = discover_python_files(self.binder.project_path)
        for py_file in python_files:
            if py_file == file_path:
                continue
            func_node = self._search_function_in_file(py_file, function_name)
            if func_node:
                self._function_lookup_cache[cache_key] = func_node
                return func_node

        # Cache None to avoid repeated searches
        self._function_lookup_cache[cache_key] = None
        return None

    def _search_function_in_file(self, file_path: Path, function_name: str) -> Optional[FunctionNode]:
        """Search for a function in a specific file.
        
        Args:
            file_path: Path to the file
            function_name: Name of the function to find
            
        Returns:
            FunctionNode if found, None otherwise
        """
        if not file_path.exists():
            return None

        tree = self.parser.parse_file(file_path)
        if not tree:
            return None

        results = self.generic_query_engine.execute_query(tree, "functions", validate_imports=False)
        for result in results:
            func_name = result.get_capture_text("function_name")
            func_node_ts = result.get_capture_node("function")

            if func_name == function_name and func_node_ts:
                module_name = file_to_module_path(file_path, self.binder.project_path)
                return FunctionNode.from_tree_sitter(
                    node=func_node_ts,
                    file_path=file_path,
                    project_path=self.binder.project_path,
                    project_hash=self.project_hash,
                    module_name=module_name,
                )

        return None
    
    # ==========================================================================
    # Flask Context Dependency Detection
    # ==========================================================================
    
    def extract_context_dependencies(self, func_node: FunctionNode) -> Set[str]:
        """Extract Flask context object usage from function.
        
        Flask provides special context objects:
        - g: request-scoped storage
        - request: current request
        - session: user session
        - current_app: current Flask application
        
        from flask import g, request, session
        
        @app.before_request
        def before_request():
            g.user = get_current_user()  # Sets g.user
        
        @app.route('/profile')
        def profile():
            user = g.user  # Uses g.user (depends on before_request)
        
        Args:
            func_node: Function node to analyze
            
        Returns:
            Set of context object names used (e.g., {'g', 'request'})
        """
        import re
        
        context_objects = {"g", "request", "session", "current_app"}
        used_contexts = set()
        
        # Get the source node (tree-sitter node)
        tree = self.parser.parse_file(func_node.path)
        if not tree:
            return used_contexts
        
        # Simple regex search in source code for context usage
        # This is efficient and doesn't require complex tree-sitter queries
        source = tree.root_node.text.decode("utf-8") if tree.root_node.text else ""
        
        for context in context_objects:
            # Check for usage: g.attr, request.method, session['key'], etc.
            # Support both dot notation and bracket notation
            if re.search(rf"\b{context}[\.\[]", source):
                used_contexts.add(context)
        
        return used_contexts
    
    def extract_context_attributes(self, func_node: FunctionNode, context_name: str) -> Set[str]:
        """Extract specific attributes accessed on context object.
        
        Example: from "user = g.user" extracts "user"
        
        Args:
            func_node: Function node
            context_name: Name of context object ('g', 'request', etc.)
            
        Returns:
            Set of attribute names
        """
        import re
        
        attributes = set()
        
        # Get the source node (tree-sitter node)
        tree = self.parser.parse_file(func_node.path)
        if not tree:
            return attributes
        
        source = tree.root_node.text.decode("utf-8") if tree.root_node.text else ""
        
        # Pattern: g.attribute or g.attribute()
        pattern = rf"\b{context_name}\.(\w+)"
        for match in re.finditer(pattern, source):
            attributes.add(match.group(1))
        
        return attributes
