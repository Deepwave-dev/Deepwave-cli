"""Tree-sitter query engine for pattern matching"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any
from tree_sitter import Tree, Node as TSNode, Language, Query, QueryCursor
from loguru import logger
from engine.parser.import_analyzer import ImportAnalyzer


@dataclass
class QueryResult:
    """Result of a Tree-sitter query execution"""

    pattern_name: str  # Name of the matched pattern
    captures: Dict[str, TSNode]  # Named captures from query (@capture_name -> TSNode)
    match_node: TSNode  # The root node of the match
    start_byte: int  # Starting byte offset
    end_byte: int  # Ending byte offset

    def get_capture_text(self, capture_name: str, default: str = "") -> str:
        """Get text content of a captured node"""
        if capture_name in self.captures:
            return self.captures[capture_name].text.decode("utf-8", errors="ignore")
        return default

    def get_capture_node(self, capture_name: str) -> Optional[TSNode]:
        """Get a captured node by name"""
        return self.captures.get(capture_name)


class QueryEngine:
    """Execute Tree-sitter queries to find patterns in code"""

    def __init__(self, parser, enable_cache: bool = True, query_subdirectory: Optional[str] = None):
        """
        Initialize QueryEngine with a parser.

        Args:
            parser: TreeSitterParser instance
            enable_cache: Whether to cache compiled queries (default: True)
            query_subdirectory: Subdirectory within language folder to load queries from.
                               If None, loads all queries from language root.
                               Examples: "generic", "frameworks/fastapi"
        """
        self.parser = parser
        self.enable_cache = enable_cache
        self.query_subdirectory = query_subdirectory
        self._query_cache: Dict[str, Query] = {}
        self._language_name = parser.get_language()
        self._import_analyzer = ImportAnalyzer()

        # Get the actual Language object from parser
        if not hasattr(parser, "language") or parser.language is None:
            raise ValueError("Parser must have a language attribute")

        self._language_obj = parser.language

        # Load queries for the parser's language
        self._load_queries()

    def _load_queries(self) -> None:
        """Load and compile all query files for the parser's language"""
        language = self._language_name
        queries_dir = self._get_queries_directory()

        if not queries_dir.exists():
            logger.warning(f"Queries directory not found: {queries_dir}")
            return

        # Determine the directory to load queries from
        language_queries_dir = queries_dir / language
        if self.query_subdirectory:
            # Load from specific subdirectory (e.g., "generic" or "frameworks/fastapi")
            language_queries_dir = language_queries_dir / self.query_subdirectory

        if not language_queries_dir.exists():
            logger.warning(f"Language queries directory not found: {language_queries_dir}")
            return

        # Load all .scm files recursively from the target directory
        for query_file in language_queries_dir.rglob("*.scm"):
            try:
                query_name = query_file.stem  # filename without .scm extension
                query_string = query_file.read_text(encoding="utf-8")

                query = self._compile_query(query_string, query_file)
                if query:
                    self._query_cache[query_name] = query
            except Exception as e:
                logger.error(f"Failed to load query from {query_file}: {e}")

    def _compile_query(self, query_string: str, query_file: Path) -> Optional[Query]:
        """Compile a query string into a Query object"""
        try:
            # Use the Language object from parser
            if self._language_obj is None:
                logger.error(f"Cannot compile query: parser language is None")
                return None

            query = Query(self._language_obj, query_string)
            return query
        except Exception as e:
            logger.error(f"Failed to compile query from {query_file}: {e}")
            return None

    def _get_queries_directory(self) -> Path:
        """Get the path to the queries directory"""
        if getattr(sys, "frozen", False):
            base_path = Path(sys._MEIPASS) / "engine" / "parser"
        else:
            base_path = Path(__file__).parent

        return base_path / "queries"

    def execute_query(self, tree: Tree, query_name: str, validate_imports: bool = True) -> List[QueryResult]:
        """
        Execute a named query against a tree.

        Args:
            tree: Tree-sitter Tree to query
            query_name: Name of the query (filename without .scm)
            validate_imports: Whether to validate results against imports (default: True)

        Returns:
            List of QueryResult objects with captures
        """
        if query_name not in self._query_cache:
            logger.warning(f"Query not found: {query_name}")
            return []

        # Analyze imports first (matches AST extractor behavior)
        if validate_imports:
            self._import_analyzer.analyze_imports(tree)

        query = self._query_cache[query_name]
        results = self._execute_compiled_query(tree, query, query_name)

        # Validate results against imports for FastAPI-specific queries
        if validate_imports and query_name in ["fastapi_apps", "routers"]:
            results = self._validate_fastapi_results(results, query_name)

        return results

    def execute_query_string(self, tree: Tree, query_string: str, pattern_name: str = "custom") -> List[QueryResult]:
        """
        Execute a raw query string (for testing).

        Args:
            tree: Tree-sitter Tree to query
            query_string: Raw query string in Tree-sitter query syntax
            pattern_name: Name to assign to the pattern (for QueryResult)

        Returns:
            List of QueryResult objects with captures
        """
        query = self._compile_query(query_string, Path(f"<{pattern_name}>"))
        if not query:
            return []

        return self._execute_compiled_query(tree, query, pattern_name)

    def _captures_to_matches(self, captures_list, query: Query) -> List:
        """Convert captures list to matches format for processing"""
        # Group captures by match (if needed)
        # For now, assume each capture is a separate match
        matches = []
        current_match = {}
        capture_names = query.capture_names

        for capture_index, node in captures_list:
            if isinstance(capture_index, int) and capture_index < len(capture_names):
                # Create a match-like object
                if not current_match:
                    current_match = {"captures": []}
                current_match["captures"].append((capture_index, node))

        if current_match:
            matches.append(current_match)

        return matches

    def _execute_compiled_query(self, tree: Tree, query: Query, pattern_name: str) -> List[QueryResult]:
        """Execute a compiled query and return structured results"""
        if not tree or not tree.root_node:
            return []

        results = []

        # Execute query using Tree-sitter Python bindings
        # Correct API: QueryCursor(query) then cursor.matches(node)
        # Signature: matches(self, node, /, predicate=None, progress_callback=None)
        cursor = QueryCursor(query)

        try:
            matches = cursor.matches(tree.root_node)
        except Exception as e:
            logger.error(f"Unable to execute query: {e}")
            return []

        # Process matches
        # Get capture names from query - use capture_name(index) method
        capture_names = []
        if hasattr(query, "capture_count"):
            for i in range(query.capture_count):
                try:
                    name = query.capture_name(i)
                    if name:
                        capture_names.append(name)
                    else:
                        capture_names.append(f"capture_{i}")
                except (IndexError, AttributeError):
                    capture_names.append(f"capture_{i}")

        try:
            # Process matches - py-tree-sitter cursor.matches() returns list of tuples
            # Each tuple is: (pattern_index, {capture_name: [nodes]})
            # Example: (0, {'var_name': [<Node>], 'func_name': [<Node>]})
            for match_item in matches:
                if isinstance(match_item, tuple) and len(match_item) >= 2:
                    pattern_index, captures_dict = match_item[0], match_item[1]

                    if isinstance(captures_dict, dict):
                        # Process captures from dict
                        processed_captures: Dict[str, TSNode] = {}
                        match_node: Optional[TSNode] = None

                        # captures_dict maps capture names to lists of nodes
                        for capture_name, nodes_list in captures_dict.items():
                            if isinstance(nodes_list, list) and len(nodes_list) > 0:
                                # Take first node if multiple
                                node = nodes_list[0]
                                processed_captures[capture_name] = node
                                if match_node is None:
                                    match_node = node

                        if processed_captures and match_node:
                            result = QueryResult(
                                pattern_name=pattern_name,
                                captures=processed_captures,
                                match_node=match_node,
                                start_byte=match_node.start_byte,
                                end_byte=match_node.end_byte,
                            )
                            results.append(result)
        except Exception:
            pass

        return results

    def _validate_fastapi_results(self, results: List[QueryResult], query_name: str) -> List[QueryResult]:
        """
        Validate query results against imports for FastAPI-specific patterns.

        Filters out assignments that aren't FastAPI() or APIRouter() instantiations.

        Args:
            results: List of query results to validate
            query_name: Name of the query being validated

        Returns:
            Filtered list of valid results
        """
        validated = []

        for result in results:
            # Get the function name from the call
            func_name_text = result.get_capture_text("func_name")

            # For fastapi_apps query
            if query_name == "fastapi_apps":
                if func_name_text and self._import_analyzer.is_fastapi_reference(func_name_text):
                    validated.append(result)

            # For routers query
            elif query_name == "routers":
                if func_name_text and self._import_analyzer.is_apirouter_reference(func_name_text):
                    validated.append(result)

        return validated

    def get_loaded_queries(self) -> List[str]:
        """Get list of all loaded query names"""
        return list(self._query_cache.keys())

    def reload_queries(self) -> None:
        """Reload queries from disk (useful for development)"""
        self._query_cache.clear()
        self._load_queries()
