import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set
from loguru import logger

from engine.models import (
    CoreGraph,
    GenericNode,
    GenericEdge,
    GenericNodeType,
    GenericEdgeType,
)
from engine.models import ProjectMetadata
from engine.parser import TreeSitterParser, QueryEngine
from engine.parser.query_engine import QueryResult
from engine.parser.parse_cache import ParseCache
from engine.ignore import discover_python_files


class CoreGraphBuilder:
    """Builds a generic, language-agnostic graph from source code."""

    def __init__(
        self,
        project_metadata: ProjectMetadata,
        project_path: Path,
        parse_cache: ParseCache,
    ):
        """Initialize the core graph builder."""
        self.project_metadata = project_metadata
        self.project_path = project_path
        self.project_hash = project_metadata.project_hash
        self.parse_cache = parse_cache
        self.parser = parse_cache.parser
        self.query_engine = QueryEngine(self.parser, query_subdirectory="generic")

        # Core graph
        self.graph: Optional[CoreGraph] = None

        # Temporary storage during build
        self._node_counter = 0
        self._edge_counter = 0
        self._file_trees: Dict[Path, any] = {}  # Cache parsed trees

    def build_graph(self, files: Optional[List[Path]] = None) -> CoreGraph:
        """Build the complete generic graph."""
        # Initialize graph
        self.graph = CoreGraph(
            project_path=self.project_path,
            project_hash=self.project_hash,
        )

        if files is None:
            files = discover_python_files(self.project_path)

        # Get parsed trees from cache or parse if needed
        for file_path in files:
            tree = self.parse_cache.get_tree(file_path)
            if not tree:
                tree = self.parser.parse_file(file_path)
                if tree:
                    self.parse_cache.store_tree(file_path, tree)
            if tree:
                self._file_trees[file_path] = tree

        # Extract nodes from all files
        self._extract_nodes()

        # Extract edges from all files
        self._extract_edges()

        return self.graph

    def _extract_nodes(self) -> None:
        """Extract all nodes from all files"""
        for file_path, tree in self._file_trees.items():
            # Extract classes
            self._extract_classes(file_path, tree)

            # Extract functions
            self._extract_functions(file_path, tree)

            # Extract assignments
            self._extract_assignments(file_path, tree)

            # Extract imports
            self._extract_imports(file_path, tree)

    def _extract_classes(self, file_path: Path, tree) -> None:
        """Extract class nodes from a file"""
        results = self.query_engine.execute_query(tree, "classes", validate_imports=False)

        for result in results:
            class_name = result.get_capture_text("class_name")
            class_node = result.get_capture_node("class")
            superclasses_node = result.get_capture_node("superclasses")

            if not class_name or not class_node:
                continue

            # Extract base classes
            base_classes = []
            if superclasses_node:
                # Iterate through children of argument_list (identifier, attribute, etc.)
                for child in superclasses_node.children:
                    if child.type in ["identifier", "attribute", "call"]:
                        base_classes.append(child.text.decode("utf-8"))

            # Create generic node
            node_id = self._generate_node_id(file_path, "class", class_name, class_node.start_point[0])

            node = GenericNode(
                id=node_id,
                node_type=GenericNodeType.CLASS,
                name=class_name,
                file_path=file_path,
                start_line=class_node.start_point[0] + 1,
                end_line=class_node.end_point[0] + 1,
                start_byte=class_node.start_byte,
                end_byte=class_node.end_byte,
                source_code=class_node.text.decode("utf-8", errors="ignore") if class_node.text else None,
                metadata={"base_classes": base_classes} if base_classes else {},
            )

            self.graph.add_node(node)

    def _extract_functions(self, file_path: Path, tree) -> None:
        """Extract function nodes from a file"""
        results = self.query_engine.execute_query(tree, "functions", validate_imports=False)

        for result in results:
            func_name = result.get_capture_text("function_name")
            func_node = result.get_capture_node("function")

            if not func_name or not func_node:
                continue

            # Determine if this is a method (inside a class) or a standalone function
            # For now, we'll mark all as FUNCTION and establish parent relationships later
            node_id = self._generate_node_id(file_path, "function", func_name, func_node.start_point[0])

            node = GenericNode(
                id=node_id,
                node_type=GenericNodeType.FUNCTION,
                name=func_name,
                file_path=file_path,
                start_line=func_node.start_point[0] + 1,
                end_line=func_node.end_point[0] + 1,
                start_byte=func_node.start_byte,
                end_byte=func_node.end_byte,
                source_code=func_node.text.decode("utf-8", errors="ignore") if func_node.text else None,
            )

            self.graph.add_node(node)

    def _extract_assignments(self, file_path: Path, tree) -> None:
        """Extract assignment nodes from a file"""
        results = self.query_engine.execute_query(tree, "assignments", validate_imports=False)

        seen_assignments = set()

        for result in results:
            var_name = result.get_capture_text("var_name")
            assignment_node = result.get_capture_node("assignment")

            if not var_name or not assignment_node:
                continue

            # Create unique key to avoid duplicates
            key = f"{file_path}:{assignment_node.start_point[0]}:{var_name}"
            if key in seen_assignments:
                continue
            seen_assignments.add(key)

            node_id = self._generate_node_id(file_path, "assignment", var_name, assignment_node.start_point[0])

            node = GenericNode(
                id=node_id,
                node_type=GenericNodeType.ASSIGNMENT,
                name=var_name,
                file_path=file_path,
                start_line=assignment_node.start_point[0] + 1,
                end_line=assignment_node.end_point[0] + 1,
                start_byte=assignment_node.start_byte,
                end_byte=assignment_node.end_byte,
                source_code=assignment_node.text.decode("utf-8", errors="ignore") if assignment_node.text else None,
            )

            self.graph.add_node(node)

    def _extract_imports(self, file_path: Path, tree) -> None:
        """Extract import nodes from a file"""
        results = self.query_engine.execute_query(tree, "imports", validate_imports=False)

        seen_imports = set()

        for result in results:
            module_name = result.get_capture_text("module_name")
            import_node = result.get_capture_node("import") or result.get_capture_node("import_from")

            if not module_name or not import_node:
                continue

            # Create unique key to avoid duplicates
            key = f"{file_path}:{import_node.start_point[0]}:{module_name}"
            if key in seen_imports:
                continue
            seen_imports.add(key)

            node_id = self._generate_node_id(file_path, "import", module_name, import_node.start_point[0])

            node = GenericNode(
                id=node_id,
                node_type=GenericNodeType.IMPORT,
                name=module_name,
                file_path=file_path,
                start_line=import_node.start_point[0] + 1,
                end_line=import_node.end_point[0] + 1,
                start_byte=import_node.start_byte,
                end_byte=import_node.end_byte,
                source_code=import_node.text.decode("utf-8", errors="ignore") if import_node.text else None,
            )

            self.graph.add_node(node)

    def _extract_edges(self) -> None:
        """Extract all edges from all files"""
        for file_path, tree in self._file_trees.items():
            # Extract call edges
            self._extract_call_edges(file_path, tree)

            # Extract contains edges (class contains method)
            self._extract_contains_edges(file_path)

            # Extract decorator edges
            self._extract_decorator_edges(file_path, tree)

        # Extract inheritance edges (child class -> parent class)
        self._extract_inheritance_edges()

    def _extract_call_edges(self, file_path: Path, tree) -> None:
        """Extract function/method call edges"""
        results = self.query_engine.execute_query(tree, "calls", validate_imports=False)

        # Get all functions in this file
        file_functions = [n for n in self.graph.get_nodes_by_file(file_path) if n.node_type == GenericNodeType.FUNCTION]

        for result in results:
            # Get call information
            func_name = result.get_capture_text("function_name")
            method_name = result.get_capture_text("method_name")
            object_name = result.get_capture_text("object_name")
            call_node = result.get_capture_node("call") or result.get_capture_node("attribute_call")

            if not call_node:
                continue

            call_line = call_node.start_point[0] + 1

            # Find the caller (which function contains this call)
            caller = None
            for func in file_functions:
                if func.start_line <= call_line <= func.end_line:
                    caller = func
                    break

            if not caller:
                continue

            # Determine the target name
            if method_name and object_name:
                target_name = method_name
            elif func_name:
                target_name = func_name
            else:
                continue

            # Find target nodes (could be multiple with same name)
            target_nodes = self.graph.get_nodes_by_name(target_name)
            target_functions = [n for n in target_nodes if n.node_type == GenericNodeType.FUNCTION]

            # Create edge for each potential target
            for target in target_functions:
                edge_id = self._generate_edge_id(caller.id, target.id, "calls")

                edge = GenericEdge(
                    id=edge_id,
                    edge_type=GenericEdgeType.CALLS,
                    source_id=caller.id,
                    target_id=target.id,
                    metadata={
                        "call_line": call_line,
                        "is_method_call": bool(method_name and object_name),
                    },
                )

                self.graph.add_edge(edge)

    def _extract_contains_edges(self, file_path: Path) -> None:
        """Extract containment edges (class contains method, module contains function)."""
        file_nodes = self.graph.get_nodes_by_file(file_path)

        # Get classes and functions
        classes = [n for n in file_nodes if n.node_type == GenericNodeType.CLASS]
        functions = [n for n in file_nodes if n.node_type == GenericNodeType.FUNCTION]

        # For each function, check if it's contained in a class
        for func in functions:
            for cls in classes:
                if cls.start_line <= func.start_line and func.end_line <= cls.end_line:
                    # Function is inside this class
                    edge_id = self._generate_edge_id(cls.id, func.id, "contains")

                    edge = GenericEdge(
                        id=edge_id,
                        edge_type=GenericEdgeType.CONTAINS,
                        source_id=cls.id,
                        target_id=func.id,
                        metadata={"container_type": "class"},
                    )

                    self.graph.add_edge(edge)

                    # Update parent-child relationship in nodes
                    func.parent_id = cls.id
                    if func.id not in cls.child_ids:
                        cls.child_ids.append(func.id)

                    # Mark function as method and update indices
                    # First remove from FUNCTION index (if it exists)
                    if GenericNodeType.FUNCTION in self.graph.nodes_by_type:
                        self.graph.nodes_by_type[GenericNodeType.FUNCTION].discard(func.id)

                    # Change type to METHOD
                    func.node_type = GenericNodeType.METHOD
                    func.metadata["is_method"] = True

                    # Add to METHOD index
                    self.graph.nodes_by_type.setdefault(GenericNodeType.METHOD, set()).add(func.id)

    def _extract_decorator_edges(self, file_path: Path, tree) -> None:
        """Extract decorator edges (decorator decorates function/class)"""
        results = self.query_engine.execute_query(tree, "decorators", validate_imports=False)

        for result in results:
            func_name = result.get_capture_text("function_name")
            class_name = result.get_capture_text("class_name")
            decorator_object = result.get_capture_text("decorator_object")
            decorator_method = result.get_capture_text("decorator_method")
            decorator_name = result.get_capture_text("decorator_name")

            target_name = func_name or class_name
            if not target_name:
                continue

            # Construct decorator identifier
            if decorator_object and decorator_method:
                decorator_identifier = f"{decorator_object}.{decorator_method}"
            elif decorator_name:
                decorator_identifier = decorator_name
            else:
                continue

            # Find target node in this file
            file_nodes = self.graph.get_nodes_by_file(file_path)
            targets = [n for n in file_nodes if n.name == target_name]

            for target in targets:
                # Create decorator node
                decorator_node_id = self._generate_node_id(
                    file_path, "decorator", decorator_identifier, target.start_line - 1
                )

                decorator_node = GenericNode(
                    id=decorator_node_id,
                    node_type=GenericNodeType.DECORATOR,
                    name=decorator_identifier,
                    file_path=file_path,
                    start_line=target.start_line - 1,
                    end_line=target.start_line - 1,
                    metadata={
                        "object": decorator_object,
                        "method": decorator_method,
                    },
                )

                self.graph.add_node(decorator_node)

                # Create edge from decorator to target
                edge_id = self._generate_edge_id(decorator_node.id, target.id, "decorates")

                edge = GenericEdge(
                    id=edge_id,
                    edge_type=GenericEdgeType.DECORATES,
                    source_id=decorator_node.id,
                    target_id=target.id,
                    metadata={"decorator": decorator_identifier},
                )

                self.graph.add_edge(edge)

    def _extract_inheritance_edges(self) -> None:
        """Extract inheritance edges between classes"""
        # Get all class nodes
        class_nodes = self.graph.get_nodes_by_type(GenericNodeType.CLASS)

        # Build a map of class names to nodes for quick lookup
        class_name_to_node = {}
        for cls_node in class_nodes:
            class_name_to_node[cls_node.name] = cls_node

        # For each class, check if it has base_classes metadata
        for child_class in class_nodes:
            base_classes = child_class.metadata.get("base_classes", [])

            for base_class_name in base_classes:
                # Try to find the parent class node
                # Handle simple names (e.g., "BaseClass")
                parent_node = class_name_to_node.get(base_class_name)

                if not parent_node:
                    # Try to extract just the class name if it's module.Class format
                    if "." in base_class_name:
                        simple_name = base_class_name.split(".")[-1]
                        parent_node = class_name_to_node.get(simple_name)

                if parent_node:
                    # Create inheritance edge
                    edge_id = self._generate_edge_id(child_class.id, parent_node.id, "inherits")

                    edge = GenericEdge(
                        id=edge_id,
                        edge_type=GenericEdgeType.INHERITS,
                        source_id=child_class.id,
                        target_id=parent_node.id,
                        metadata={"inheritance_type": "class"},
                    )

                    self.graph.add_edge(edge)

    def _generate_node_id(self, file_path: Path, node_type: str, name: str, line: int) -> str:
        """Generate a unique node ID"""
        # Use file path, type, name, and line to create unique ID
        unique_str = f"{file_path}:{node_type}:{name}:{line}"
        hash_str = hashlib.md5(unique_str.encode()).hexdigest()[:12]
        return f"{self.project_hash}:{node_type}:{hash_str}"

    def _generate_edge_id(self, source_id: str, target_id: str, edge_type: str) -> str:
        """Generate a unique edge ID"""
        unique_str = f"{source_id}:{target_id}:{edge_type}"
        hash_str = hashlib.md5(unique_str.encode()).hexdigest()[:12]
        return f"{self.project_hash}:{edge_type}:{hash_str}"
