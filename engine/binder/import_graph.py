"""Tree-sitter based ImportGraph - maintains 100% compatibility with AST version"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple
from loguru import logger

from engine.parser import TreeSitterParser, QueryEngine
from engine.parser.import_analyzer import ImportAnalyzer
from engine.parser.import_info import ImportInfo
from engine.parser.parse_cache import ParseCache
from engine.ignore import file_to_module_path


class ImportGraph:
    """Project-wide import resolver using Tree-sitter - drop-in replacement for ImportGraph"""

    def __init__(self, project_path: Path, parse_cache: ParseCache) -> None:
        self.project_path = project_path
        self.parse_cache = parse_cache
        self.parser = parse_cache.parser
        self.query_engine = QueryEngine(self.parser)
        self.import_analyzer = ImportAnalyzer()

        # module_name -> file_path
        self.module_to_file: Dict[str, Path] = {}
        # file_path_rel -> { local_name -> (source_module, source_symbol_or_None) }
        self.file_imports: Dict[str, Dict[str, Tuple[str, Optional[str]]]] = {}

    def build(self, python_files: List[Path]) -> None:
        """
        Build the import graph from all Python files using Tree-sitter.
        Matches AST ImportGraph.build() behavior exactly.
        """
        # First pass: collect all imports to detect the import root
        all_imports = set()
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

                # Extract all imports using ImportAnalyzer
                import_infos = self.import_analyzer.extract_all_imports(tree)
                for import_info in import_infos:
                    if import_info.module_name:
                        all_imports.add(import_info.module_name.split(".")[0])
            except Exception as e:
                logger.debug(f"Failed to parse {file_path} for import root detection: {e}")
                continue

        # Detect import root by finding common prefix to strip
        import_root_offset = self._detect_import_root(python_files, all_imports)

        # Index modules with the correct import root
        for file_path in python_files:
            module_name = self._module_name_from_path(file_path, import_root_offset)
            self.module_to_file[module_name] = file_path

        # Second pass: build import map for each file
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
            except Exception as e:
                logger.debug(f"Failed to parse {file_path} for import extraction: {e}")
                continue

            rel = self._rel(file_path)
            imports: Dict[str, Tuple[str, Optional[str]]] = {}
            # Compute current module for resolving relative imports
            current_module = self._module_name_from_path(file_path, import_root_offset)

            # Extract all imports using ImportAnalyzer
            import_infos = self.import_analyzer.extract_all_imports(tree)

            for import_info in import_infos:
                if import_info.import_type == "import":
                    # import module [as alias]
                    # ImportInfo.imports contains (module_name, alias) tuples
                    for module_name, alias in import_info.imports:
                        # local = alias or first part of module name (matches AST behavior)
                        local = alias or module_name.split(".")[0]
                        imports[local] = (module_name, None)

                elif import_info.import_type == "import_from":
                    # from module import name [as alias], ...
                    # Resolve relative imports
                    effective_module: Optional[str]
                    if import_info.level > 0:
                        parts = current_module.split(".")
                        base_parts = parts[: max(0, len(parts) - import_info.level)]
                        if import_info.module_name:
                            effective_module = (
                                ".".join([*base_parts, import_info.module_name])
                                if base_parts
                                else import_info.module_name
                            )
                        else:
                            effective_module = None
                    else:
                        effective_module = import_info.module_name

                    if effective_module is None:
                        # from . import foo, bar
                        # Recompute base_parts (they were computed above but may not be in scope)
                        parts = current_module.split(".")
                        base_parts = parts[: max(0, len(parts) - import_info.level)]
                        for name, alias in import_info.imports:
                            local = alias or name
                            # Build target_module: base_parts + name
                            if base_parts:
                                target_module = ".".join([*base_parts, name])
                            else:
                                target_module = name
                            imports[local] = (target_module, name)
                    else:
                        for name, alias in import_info.imports:
                            local = alias or name
                            imports[local] = (effective_module, name)

            self.file_imports[rel] = imports

    def resolve_name(self, file_path: Path, local_name: str) -> Optional[Tuple[str, Optional[str]]]:
        """
        Return (module, symbol_or_None) where local_name came from for this file, if imported.
        Matches AST ImportGraph.resolve_name() behavior exactly.
        """
        rel = self._rel(file_path)
        imports = self.file_imports.get(rel, {})
        result = imports.get(local_name)
        if not result:
            return None

        module, symbol = result
        # If alias refers to a submodule (from pkg import subpkg), promote to full module path
        if symbol:
            combined = f"{module}.{symbol}"
            if combined in self.module_to_file:
                return (combined, None)

        return (module, symbol)

    def file_for_module(self, module_name: str) -> Optional[Path]:
        """
        Resolve module name to file path.
        Modules are indexed with correct import root, so direct lookup should work.
        Matches AST ImportGraph.file_for_module() behavior exactly.
        """
        path = self.module_to_file.get(module_name)
        if path:
            return path
        # Heuristic: support 'src/' package layout discrepancies between imports and filesystem
        if module_name.startswith("src."):
            alt = module_name[len("src.") :]
            path = self.module_to_file.get(alt)
            if path:
                return path
        else:
            alt = f"src.{module_name}"
            path = self.module_to_file.get(alt)
            if path:
                return path
        return None

    def _detect_import_root(self, python_files: List[Path], imported_modules: set) -> int:
        """
        Detect how many path components to skip to match import statements.
        Returns the number of components to strip from the beginning of paths.
        Matches AST ImportGraph._detect_import_root() behavior exactly.
        """
        if not imported_modules:
            return 0

        # Look at file paths and see which ones match imported module roots
        for file_path in python_files:
            rel = self._rel(file_path)
            parts = rel.replace(".py", "").replace("/__init__", "").split("/")

            # Check if any suffix of the path matches an imported module
            for i in range(len(parts)):
                if parts[i] in imported_modules:
                    # Found the import root at position i
                    return i

        return 0  # Default: no offset

    def _module_name_from_path(self, file_path: Path, offset: int = 0) -> str:
        """Convert file path to module name using path_utils."""
        module_name = file_to_module_path(file_path, self.project_path)

        # Apply offset to strip leading path components
        if offset > 0:
            parts = module_name.split(".")
            if len(parts) > offset:
                module_name = ".".join(parts[offset:])

        return module_name

    def _rel(self, file_path: Path) -> str:
        """Get relative path from project root"""
        return str(file_path.relative_to(self.project_path))
