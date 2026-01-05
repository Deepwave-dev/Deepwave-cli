from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from loguru import logger
from tree_sitter import Tree, Node as TSNode

from engine.models import FunctionNode, NodeType
from engine.models import GraphEdge, EdgeRelation
from engine.models import CoreGraph, GenericNode, GenericNodeType
from engine.binder.symbol_resolver import SymbolResolver
from engine.parser import TreeSitterParser, QueryEngine
from engine.parser.parse_cache import ParseCache
from engine.ignore import file_to_module_path


@dataclass
class CallGraphResult:
    """Result of call graph building process"""

    function_nodes: List[GenericNode]
    call_edges: List[GraphEdge]
    caller_map: Dict[str, Set[str]]  # function_id -> set of caller function_ids


class CallGraphBuilderTreeSitter:
    """Builds call graph by reusing function definitions from CoreGraph."""

    def __init__(
        self,
        project_hash: str,
        project_path: Path,
        core_graph: CoreGraph,
        binder: SymbolResolver,
        parse_cache: ParseCache,
    ):
        self.project_hash = project_hash
        self.project_path = project_path
        self.core_graph = core_graph
        self.binder = binder
        self.parse_cache = parse_cache
        self.parser = parse_cache.parser
        self.query_engine = QueryEngine(self.parser)

    def build(self, python_files: List[Path]) -> CallGraphResult:
        """Build call graph by reusing function definitions from CoreGraph and extracting call edges."""
        call_edges: List[GraphEdge] = []

        # Get all function and method nodes from CoreGraph (already extracted!)
        functions = self.core_graph.get_nodes_by_type(GenericNodeType.FUNCTION)
        methods = self.core_graph.get_nodes_by_type(GenericNodeType.METHOD)
        function_nodes = functions + methods

        # Create a lookup map: node_id -> GenericNode
        function_map: Dict[str, GenericNode] = {fn.id: fn for fn in function_nodes}

        # Extract all function calls and match to definitions
        for file_path in python_files:
            try:
                # Use cache or parse if not cached
                tree = self.parse_cache.get_tree(file_path)
                if not tree:
                    tree = self.parser.parse_file(file_path)
                    if tree:
                        self.parse_cache.store_tree(file_path, tree)
                if not tree:
                    continue
                file_edges = self._extract_function_calls(tree, file_path, function_map)
                call_edges.extend(file_edges)
            except Exception:
                logger.exception(f"Call graph: failed extracting calls for {file_path}")
                continue

        caller_map = self._build_caller_map(call_edges)
        logger.info(f"Call graph built: {len(function_nodes)} functions, {len(call_edges)} call edges")

        return CallGraphResult(
            function_nodes=function_nodes,
            call_edges=call_edges,
            caller_map=caller_map,
        )

    def _extract_function_calls(
        self, tree: Tree, file_path: Path, function_map: Dict[str, GenericNode]
    ) -> List[GraphEdge]:
        """Extract all function calls from a tree and create edges."""
        edges: List[GraphEdge] = []
        module_name = file_to_module_path(file_path, self.project_path)

        # Hierarchical traversal to maintain context (same as original)
        def traverse(node: TSNode, context_path: List[str] = None):
            """Recursively traverse Tree-sitter tree with context tracking"""
            if context_path is None:
                context_path = []

            if node.type == "class_definition":
                # Enter class context
                name_node = node.child_by_field_name("name")
                if name_node:
                    class_name = name_node.text.decode("utf-8")
                    new_context = context_path + [f"class:{class_name}"]
                    body = node.child_by_field_name("body")
                    if body:
                        for child in body.children:
                            traverse(child, new_context)

            elif node.type == "function_definition":
                # Check for @overload decorator
                parent = self._get_parent_node(node, tree.root_node)
                if parent and parent.type == "decorated_definition":
                    if self._is_overload_decorated(parent):
                        return

                # Build function ID using shared utility
                caller_id, _ = self._build_function_id(node, module_name, context_path)

                # Skip if caller not in function_map (shouldn't happen but defensive)
                if caller_id not in function_map:
                    # Still traverse children to find nested functions
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        func_name = name_node.text.decode("utf-8")
                        new_context = context_path + [f"func:{func_name}"]
                        body = node.child_by_field_name("body")
                        if body:
                            for child in body.children:
                                traverse(child, new_context)
                    return

                # Find all calls within this function (including nested functions)
                call_nodes = self._find_all_calls(node)
                # Filter out the function node itself
                call_nodes = [cn for cn in call_nodes if cn != node]

                for call_node in call_nodes:
                    # Try to resolve the called function
                    called_function_id = self._resolve_called_function(call_node, file_path, module_name, function_map)

                    if called_function_id and called_function_id in function_map:
                        # Create calls_function edge
                        edge_id = f"edge.{self.project_hash}.calls_function.{caller_id}.{called_function_id}"
                        edge = GraphEdge(
                            id=edge_id,
                            src_id=caller_id,
                            dst_id=called_function_id,
                            relation=EdgeRelation.calls_function,
                            project_hash=self.project_hash,
                        )
                        edges.append(edge)

                # Traverse nested functions with updated context
                name_node = node.child_by_field_name("name")
                if name_node:
                    func_name = name_node.text.decode("utf-8")
                    new_context = context_path + [f"func:{func_name}"]
                    body = node.child_by_field_name("body")
                    if body:
                        for child in body.children:
                            traverse(child, new_context)

            # Handle decorated_definition wrapper
            elif node.type == "decorated_definition":
                definition = node.child_by_field_name("definition")
                if definition:
                    traverse(definition, context_path)

            # Traverse other nodes
            else:
                for child in node.children:
                    traverse(child, context_path)

        # Start traversal from module body
        root = tree.root_node
        if root.type == "module":
            for child in root.children:
                traverse(child, [])

        return edges

    def _resolve_called_function(
        self, call_node: TSNode, file_path: Path, module_name: str, function_map: Dict[str, GenericNode]
    ) -> Optional[str]:
        """Resolve a function call to its function ID."""
        try:
            func = call_node.child_by_field_name("function")
            if not func:
                return None

            if func.type == "identifier":
                # Direct call: foo()
                func_name = func.text.decode("utf-8")

                # Try local function in same module first
                candidate_id = f"function.{self.project_hash}.{module_name}.{func_name}"
                if candidate_id in function_map:
                    return candidate_id

                # Try to resolve as imported function using binder
                try:
                    resolved = self.binder.import_graph.resolve_name(file_path, func_name)
                    if resolved:
                        source_module, source_symbol = resolved
                        source_func_id = f"function.{self.project_hash}.{source_module}.{source_symbol or func_name}"
                        if source_func_id in function_map:
                            return source_func_id
                except Exception:
                    pass

                # Fallback: try to find any function with matching name (less precise but helpful)
                for func_id, func_node in function_map.items():
                    if func_node.function_name == func_name:
                        return func_id

            elif func.type == "attribute":
                # Method/attribute call: obj.foo() or module.foo()
                object_node = func.child_by_field_name("object")
                attribute_node = func.child_by_field_name("attribute")
                if not object_node or not attribute_node:
                    return None

                module_or_obj = object_node.text.decode("utf-8")
                method_name = attribute_node.text.decode("utf-8")

                # First, try to bind the object to see if it's a service instance or imported object
                try:
                    if object_node.type == "identifier":
                        bound_object = self.binder.resolve_identifier(file_path, object_node)
                        if bound_object:
                            # Object resolved to a service class or other node
                            # Look for method in the service class
                            if hasattr(bound_object, "class_name"):
                                # This is a ServiceClassNode - find the method
                                # Search through function_map for methods matching class_name.method_name
                                class_name = bound_object.class_name
                                for func_id, func_node in function_map.items():
                                    if func_node.parent_class == class_name and func_node.function_name == method_name:
                                        return func_id
                except Exception:
                    pass

                # Fallback: Try to resolve as module import
                try:
                    resolved = self.binder.import_graph.resolve_name(file_path, module_or_obj)
                    if resolved:
                        source_module, _ = resolved
                        # Function is in the imported module
                        source_func_id = f"function.{self.project_hash}.{source_module}.{method_name}"
                        if source_func_id in function_map:
                            return source_func_id
                except Exception:
                    pass

        except Exception:
            pass

        return None

    def _build_caller_map(self, call_edges: List[GraphEdge]) -> Dict[str, Set[str]]:
        """Build a map of function_id -> set of caller function_ids."""
        caller_map: Dict[str, Set[str]] = {}

        for edge in call_edges:
            if edge.relation == EdgeRelation.calls_function:
                callee_id = edge.dst_id
                caller_id = edge.src_id

                if callee_id not in caller_map:
                    caller_map[callee_id] = set()
                caller_map[callee_id].add(caller_id)

        return caller_map

    def _build_function_id(
        self, func_node: TSNode, module_name: str, context_path: List[str]
    ) -> Tuple[str, Optional[str]]:
        """Build a function ID using hierarchical context."""
        # Determine parent class from context
        parent_class = None
        for ctx in context_path:
            if ctx.startswith("class:"):
                parent_class = ctx.split(":", 1)[1]
                break

        # Build context suffix for nested functions
        func_contexts = [ctx.split(":", 1)[1] for ctx in context_path if ctx.startswith("func:")]
        context_suffix = ""
        if func_contexts:
            context_suffix = "." + ".".join(func_contexts)

        # Get function name
        name_node = func_node.child_by_field_name("name")
        if not name_node:
            return "", None

        func_name = name_node.text.decode("utf-8")

        # Determine if line suffix is needed (for _, <lambda>, singledispatch)
        needs_line_suffix = func_name in ("_", "<lambda>")
        if not needs_line_suffix:
            # Check for singledispatch decorator
            parent = self._get_parent_node(func_node, func_node)
            if parent and parent.type == "decorated_definition":
                decorators = parent.children
                for dec in decorators:
                    if dec.type == "decorator":
                        dec_call = dec.child_by_field_name("decorator")
                        if dec_call and dec_call.type == "attribute":
                            attr = dec_call.child_by_field_name("attribute")
                            if attr and "register" in attr.text.decode("utf-8"):
                                needs_line_suffix = True
                                break

        start_line = func_node.start_point[0] + 1
        line_suffix = f".L{start_line}" if needs_line_suffix else ""

        # Generate function ID
        if parent_class:
            func_id = (
                f"function.{self.project_hash}.{module_name}.{parent_class}{context_suffix}.{func_name}{line_suffix}"
            )
        else:
            func_id = f"function.{self.project_hash}.{module_name}{context_suffix}.{func_name}{line_suffix}"

        return func_id, parent_class

    def _is_overload_decorated(self, decorated_node: TSNode) -> bool:
        """Check if a function is decorated with @overload"""
        for child in decorated_node.children:
            if child.type == "decorator":
                decorator = child.child_by_field_name("decorator")
                if decorator:
                    if decorator.type == "identifier" and decorator.text.decode("utf-8") == "overload":
                        return True
                    elif decorator.type == "attribute":
                        attr = decorator.child_by_field_name("attribute")
                        if attr and attr.text.decode("utf-8") == "overload":
                            return True
        return False

    def _find_all_calls(self, node: TSNode) -> List[TSNode]:
        """Find all call nodes within a node (mirrors ast.walk behavior)"""
        calls = []

        def traverse(n: TSNode):
            if n.type == "call":
                calls.append(n)
            for child in n.children:
                traverse(child)

        traverse(node)
        return calls

    def _get_parent_node(self, node: TSNode, root: TSNode) -> Optional[TSNode]:
        """Find parent node by traversing up the tree"""
        # Build parent map
        parent_map: Dict[TSNode, TSNode] = {}

        def build_map(n: TSNode, parent: Optional[TSNode] = None):
            if parent:
                parent_map[n] = parent
            for child in n.children:
                build_map(child, n)

        build_map(root)

        return parent_map.get(node)
