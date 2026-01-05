from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger
from tree_sitter import Node as TSNode

from engine.binder import ImportGraph
from engine.ignore import discover_python_files
from engine.models import ApplicationNode, ExpressionType, GenericNode, RouterNode, ServiceClassNode
from engine.parser import ParseCache, QueryEngine


class SymbolIndex:
    """Read-only symbol index built from existing nodes; plus in-memory instance index using Tree-sitter."""

    def __init__(self, project_hash: str, project_path: Path, import_graph: ImportGraph, parse_cache: ParseCache):
        self.project_hash = project_hash
        self.project_path = project_path
        self.import_graph = import_graph
        self.parse_cache = parse_cache

        self.query_engine = QueryEngine(self.parse_cache.parser)

        # (file_rel, var) -> node
        self.app_vars: Dict[Tuple[str, str], ApplicationNode] = {}
        self.router_vars: Dict[Tuple[str, str], RouterNode] = {}
        # class_name -> ServiceClassNode
        self.service_classes: Dict[str, ServiceClassNode] = {}
        # (file_rel, var) -> ServiceClassNode
        self.service_instances: Dict[Tuple[str, str], ServiceClassNode] = {}
        # (module_path, var) -> node (e.g., app.routers, V1)
        self.app_by_module: Dict[Tuple[str, str], ApplicationNode] = {}
        self.router_by_module: Dict[Tuple[str, str], RouterNode] = {}
        # (file_rel, func_name) -> RouterNode (for factory functions)
        self.router_factory_functions: Dict[Tuple[str, str], RouterNode] = {}
        # (file_rel, function_name) -> return_type_name (for dependency injection)
        self._function_return_types: Dict[Tuple[str, str], str] = {}

    def _module_path_from_file_rel(self, file_rel: str) -> str:
        """
        Convert file path to module path using ImportGraph's normalization.
        This ensures consistent module path normalization across the system.
        MUST use ImportGraph's module_to_file mapping to get the exact same module path.
        """
        if not self.import_graph:
            # Should not happen in normal operation, but defensive
            rel = file_rel
            if rel.endswith("/__init__.py"):
                rel = rel[: -len("/__init__.py")]
            elif rel.endswith(".py"):
                rel = rel[: -len(".py")]
            return rel.replace("/", ".")

        # Use ImportGraph's module lookup - this is the authoritative source
        # Convert file_rel to Path and look up in module_to_file
        # This ensures we use the EXACT same module path that ImportGraph uses
        try:
            file_path = self.project_path / file_rel
            # Find the module name that points to this file
            # ImportGraph already normalized all module paths correctly with import root detection
            for module_name, module_file in self.import_graph.module_to_file.items():
                if module_file == file_path:
                    return module_name
        except Exception:
            pass

        # If not found in module_to_file (shouldn't happen, but defensive),
        # This means the file wasn't indexed by ImportGraph, which shouldn't happen
        # Return a fallback but this indicates a bug
        rel = file_rel
        if rel.endswith("/__init__.py"):
            rel = rel[: -len("/__init__.py")]
        elif rel.endswith(".py"):
            rel = rel[: -len(".py")]

        return rel.replace("/", ".")

    def index_applications(self, applications: List[ApplicationNode]) -> None:
        """Index ApplicationNode instances for Binder resolution."""
        for app_node in applications:
            # app_node.path is a string (relative path), convert to Path for _rel
            file_path = self.project_path / app_node.path
            file_rel = self._rel(file_path)
            module_path = self._module_path_from_file_rel(file_rel)

            self.app_vars[(file_rel, app_node.app_var)] = app_node
            self.app_by_module[(module_path, app_node.app_var)] = app_node

    def index_routers(self, routers: List[RouterNode]) -> None:
        """Index RouterNode instances for Binder resolution."""
        for router_node in routers:
            # router_node.path is a string (relative path), convert to Path for _rel
            file_path = self.project_path / router_node.path
            file_rel = self._rel(file_path)
            module_path = self._module_path_from_file_rel(file_rel)

            self.router_vars[(file_rel, router_node.router_var)] = router_node
            self.router_by_module[(module_path, router_node.router_var)] = router_node

        # Also index factory functions that return routers
        self._index_router_factories(routers)

    def index_services(self, services: List[GenericNode]) -> None:
        """
        Index services discovered by FastAPIFilter (or other framework filters).

        This replaces the service discovery logic that was previously in build_instance_index().
        FastAPIFilter is now the source of truth for which services exist.
        """

        for generic_node in services:
            if generic_node.name not in self.service_classes:
                file_rel = self._rel(generic_node.file_path)
                module_path = self._module_path_from_file_rel(file_rel)

                service_node = ServiceClassNode(
                    id=f"service.{self.project_hash}.{generic_node.name}",
                    project_hash=self.project_hash,
                    name=generic_node.name,
                    path=file_rel,
                    summary=f"Service: {generic_node.name}",
                    class_name=generic_node.name,
                    module_path=module_path,
                    methods=[],
                    start_line=generic_node.start_line,
                )
                self.service_classes[generic_node.name] = service_node

    def build_instance_index(self, python_files: List[Path]) -> None:
        """
        Scan files for module-scope assigns of service instances: x = ServiceClass().

        Note: Service discovery is now done by FastAPIFilter and passed via index_services().
        This method only handles instance indexing (mapping instances to service classes).
        """
        # Find service instances
        for file_path in python_files:
            try:
                # Use cache or parse if not cached
                tree = self.parse_cache.get_tree(file_path)
                if not tree:
                    tree = self.parse_cache.parser.parse_file(file_path)
                    if tree:
                        self.parse_cache.store_tree(file_path, tree)
                if not tree:
                    continue
            except Exception:
                logger.exception(f"Symbol index: failed parsing {file_path} for service instance indexing")
                continue

            file_rel = self._rel(file_path)
            root_node = tree.root_node

            # Find all assignments using Tree-sitter query
            # Pattern: (assignment left: (identifier) @var_name right: (call function: (identifier) @class_name))
            query_string = """
            (assignment
              left: (identifier) @var_name
              right: (call
                function: (identifier) @class_name
              )
            )
            """
            results = self.query_engine.execute_query_string(tree, query_string, "service_instances")

            for result in results:
                var_name_node = result.captures.get("var_name")
                class_name_node = result.captures.get("class_name")

                if not var_name_node or not class_name_node:
                    continue

                # Only process top-level assignments (direct children of module)
                # This matches AST behavior which only checks mod.body
                assignment_node = result.match_node
                if assignment_node.type != "assignment":
                    # Find the assignment node parent
                    assignment_node = var_name_node.parent
                    while assignment_node and assignment_node.type != "assignment":
                        assignment_node = assignment_node.parent

                if not assignment_node:
                    continue

                # Check if this assignment is at the top level
                # In Tree-sitter, assignments can be:
                # 1. Direct children of module (rare)
                # 2. Children of expression_statement which is a direct child of module (common)
                is_top_level = False
                parent = assignment_node.parent

                # Check if assignment is direct child
                for child in root_node.children:
                    if child == assignment_node:
                        is_top_level = True
                        break

                # Check if assignment is in expression_statement that is direct child
                if not is_top_level and parent:
                    for child in root_node.children:
                        if child == parent and child.type == "expression_statement":
                            is_top_level = True
                            break

                if not is_top_level:
                    continue

                var_name = var_name_node.text.decode("utf-8")
                class_name = class_name_node.text.decode("utf-8")

                svc = self.service_classes.get(class_name)
                if not svc:
                    continue

                self.service_instances[(file_rel, var_name)] = svc

            # Also handle attribute-based calls: x = module.ServiceClass()
            # Extract class name from attribute (e.g., module.ServiceClass -> ServiceClass)
            query_string_attr = """
            (assignment
              left: (identifier) @var_name
              right: (call
                function: (attribute
                  object: (identifier) @module_name
                  attribute: (identifier) @class_name
                )
              )
            )
            """
            results_attr = self.query_engine.execute_query_string(tree, query_string_attr, "service_instances_attr")

            for result in results_attr:
                var_name_node = result.captures.get("var_name")
                class_name_node = result.captures.get("class_name")

                if not var_name_node or not class_name_node:
                    continue

                # Only process top-level assignments (direct children of module)
                assignment_node = result.match_node
                if assignment_node.type != "assignment":
                    assignment_node = var_name_node.parent
                    while assignment_node and assignment_node.type != "assignment":
                        assignment_node = assignment_node.parent

                if not assignment_node:
                    continue

                # Check if this assignment is at the top level
                is_top_level = False
                parent = assignment_node.parent

                # Check if assignment is direct child
                for child in root_node.children:
                    if child == assignment_node:
                        is_top_level = True
                        break

                # Check if assignment is in expression_statement that is direct child
                if not is_top_level and parent:
                    for child in root_node.children:
                        if child == parent and child.type == "expression_statement":
                            is_top_level = True
                            break

                if not is_top_level:
                    continue

                var_name = var_name_node.text.decode("utf-8")
                class_name = class_name_node.text.decode("utf-8")

                svc = self.service_classes.get(class_name)
                if not svc:
                    continue

                self.service_instances[(file_rel, var_name)] = svc

            # THIRD QUERY: Find instance attributes: self.service = ServiceClass()
            # This is common in __init__ methods where services are instantiated as attributes
            query_string_self = """
            (assignment
              left: (attribute
                object: (identifier) @self_ref
                attribute: (identifier) @attr_name
              )
              right: (call
                function: (identifier) @class_name
              )
            )
            """
            results_self = self.query_engine.execute_query_string(tree, query_string_self, "service_instances_self")

            for result in results_self:
                self_ref_node = result.captures.get("self_ref")
                attr_name_node = result.captures.get("attr_name")
                class_name_node = result.captures.get("class_name")

                if not self_ref_node or not attr_name_node or not class_name_node:
                    continue

                # Check if the object is "self" (most common case)
                self_ref = self_ref_node.text.decode("utf-8")
                if self_ref != "self":
                    # Also support "cls" for class methods
                    if self_ref != "cls":
                        continue

                attr_name = attr_name_node.text.decode("utf-8")
                class_name = class_name_node.text.decode("utf-8")

                svc = self.service_classes.get(class_name)
                if not svc:
                    continue

                self.service_instances[(file_rel, attr_name)] = svc

            # Fourth query: Find instance attributes with module prefix: self.service = module.ServiceClass()
            query_string_self_attr = """
            (assignment
              left: (attribute
                object: (identifier) @self_ref
                attribute: (identifier) @attr_name
              )
              right: (call
                function: (attribute
                  object: (identifier) @module_name
                  attribute: (identifier) @class_name
                )
              )
            )
            """
            results_self_attr = self.query_engine.execute_query_string(
                tree, query_string_self_attr, "service_instances_self_attr"
            )

            for result in results_self_attr:
                self_ref_node = result.captures.get("self_ref")
                attr_name_node = result.captures.get("attr_name")
                class_name_node = result.captures.get("class_name")

                if not self_ref_node or not attr_name_node or not class_name_node:
                    continue

                # Check if the object is "self" or "cls"
                self_ref = self_ref_node.text.decode("utf-8")
                if self_ref not in ("self", "cls"):
                    continue

                attr_name = attr_name_node.text.decode("utf-8")
                class_name = class_name_node.text.decode("utf-8")

                svc = self.service_classes.get(class_name)
                if not svc:
                    continue

                self.service_instances[(file_rel, attr_name)] = svc

    def find_app(self, file_rel: str, var: str) -> Optional[ApplicationNode]:
        return self.app_vars.get((file_rel, var))

    def find_router(self, file_rel: str, var: str) -> Optional[RouterNode]:
        return self.router_vars.get((file_rel, var))

    def find_app_by_module(self, module_path: str, var: str) -> Optional[ApplicationNode]:
        return self.app_by_module.get((module_path, var))

    def find_router_by_module(self, module_path: str, var: str) -> Optional[RouterNode]:
        return self.router_by_module.get((module_path, var))

    def find_service_instance(self, file_rel: str, var: str) -> Optional[ServiceClassNode]:
        return self.service_instances.get((file_rel, var))

    def find_service_class(self, class_name: str) -> Optional[ServiceClassNode]:
        return self.service_classes.get(class_name)

    def _index_router_factories(self, routers: List[RouterNode]) -> None:
        """
        Index factory functions that return routers.

        Example:
        def get_user_router() -> APIRouter:
            return user_router

        This allows resolve_router_factory to find routers from function calls.
        """
        # Build a set of router variables for quick lookup
        router_vars = {(self._rel(self.project_path / r.path), r.router_var) for r in routers}

        # Scan all Python files for functions that return routers
        python_files = discover_python_files(self.project_path)

        for py_file in python_files:
            try:
                # Use cache if available, otherwise parse
                if self.parse_cache:
                    tree = self.parse_cache.get_tree(py_file)
                    if not tree:
                        tree = self.parse_cache.parser.parse_file(py_file)
                        if tree:
                            self.parse_cache.store_tree(py_file, tree)
                else:
                    tree = self.parse_cache.parser.parse_file(py_file)
                if not tree:
                    continue
            except Exception:
                continue

            file_rel = self._rel(py_file)

            # Find all function definitions
            query_string = """
            (function_definition
              name: (identifier) @func_name
              return_type: (type)? @return_type
              body: (block) @body
            )
            """
            results = self.query_engine.execute_query_string(tree, query_string, "function_returns")

            for result in results:
                func_name_node = result.captures.get("func_name")
                body_node = result.captures.get("body")

                if not func_name_node or not body_node:
                    continue

                func_name = func_name_node.text.decode("utf-8")

                # Check if body contains a return statement with a router variable
                returned_router = self._find_returned_router(body_node, file_rel, router_vars)
                if returned_router:
                    self.router_factory_functions[(file_rel, func_name)] = returned_router

    def _find_returned_router(self, body_node, file_rel: str, router_vars: set) -> Optional[RouterNode]:
        """Find if function body returns a known router variable."""

        # Look for return statements in the body
        def find_returns(node):
            returns = []
            if node.type == "return_statement":
                returns.append(node)
            for child in node.children:
                returns.extend(find_returns(child))
            return returns

        return_stmts = find_returns(body_node)

        for ret_stmt in return_stmts:
            # Get the expression being returned
            for child in ret_stmt.children:
                if child.type == ExpressionType.IDENTIFIER:
                    var_name = child.text.decode("utf-8")
                    # Check if this variable is a known router
                    if (file_rel, var_name) in router_vars:
                        return self.router_vars.get((file_rel, var_name))

        return None

    def resolve_router_factory(self, file_rel: str, func_name: str) -> Optional[RouterNode]:
        """Resolve a factory function to the router it returns."""
        return self.router_factory_functions.get((file_rel, func_name))

    def _rel(self, file_path: Path) -> str:
        return str(file_path.relative_to(self.project_path))

    def index_function_return_type(self, file_path: Path, function_name: str, return_type_name: str) -> None:
        """Index a function's return type for later lookup."""
        file_rel = self._rel(file_path)
        self._function_return_types[(file_rel, function_name)] = return_type_name

    def get_function_return_type(self, file_path: Path, function_name: str) -> Optional[str]:
        """Get a function's return type if it's been indexed."""
        file_rel = self._rel(file_path)
        return self._function_return_types.get((file_rel, function_name))

    def infer_and_index_return_types(self, files: List[Path]) -> None:
        """
        Infer and index return types for all functions in the given files.

        This enhances return type tracking by:
        1. Extracting explicit type annotations from function signatures
        2. Inferring types from return statements (class instantiations)
        """
        for file_path in files:
            if not file_path.exists():
                continue

            # Use cache if available, otherwise parse
            if self.parse_cache:
                tree = self.parse_cache.get_tree(file_path)
                if not tree:
                    tree = self.parse_cache.parser.parse_file(file_path)
                    if tree:
                        self.parse_cache.store_tree(file_path, tree)
            else:
                tree = self.parse_cache.parser.parse_file(file_path)
            if not tree:
                continue

            # Find all function definitions
            results = self.query_engine.execute_query(tree, "functions", validate_imports=False)

            for result in results:
                func_name = result.get_capture_text("function_name")
                func_node = result.get_capture_node("function")

                if not func_name or not func_node:
                    continue

                # 1. Check for explicit return type annotation
                return_type = self._extract_return_type_annotation(func_node)
                if return_type:
                    self.index_function_return_type(file_path, func_name, return_type)
                    continue

                # 2. Infer from return statements
                inferred_type = self._infer_return_type_from_body(func_node)
                if inferred_type:
                    self.index_function_return_type(file_path, func_name, inferred_type)

    def _extract_return_type_annotation(self, func_node: TSNode) -> Optional[str]:
        """Extract return type from function signature annotation."""
        # Look for return type annotation: def func() -> ReturnType:
        for child in func_node.children:
            if child.type == "type":
                # This is the return type annotation
                return child.text.decode("utf-8", errors="ignore").strip()

        return None

    def _infer_return_type_from_body(self, func_node: TSNode) -> Optional[str]:
        """Infer return type from return statements in function body."""
        # Find return statements in the function
        return_statements = self._find_return_statements(func_node)

        for return_node in return_statements:
            # Look for class instantiation pattern: return ClassName()
            for child in return_node.children:
                if child.type == ExpressionType.CALL:
                    # Get the function being called
                    func_child = child.child_by_field_name("function")
                    if func_child and func_child.type == ExpressionType.IDENTIFIER:
                        class_name = func_child.text.decode("utf-8", errors="ignore")
                        # Simple heuristic: if it starts with uppercase, it's likely a class
                        if class_name and class_name[0].isupper():
                            return class_name

        return None

    def _find_return_statements(self, node: TSNode) -> List[TSNode]:
        """Recursively find all return statements in a node."""
        return_statements = []

        if node.type == "return_statement":
            return_statements.append(node)

        for child in node.children:
            return_statements.extend(self._find_return_statements(child))

        return return_statements
