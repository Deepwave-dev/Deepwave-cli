"""Import analysis for Tree-sitter parsed code - matches AST import analysis"""

from typing import Dict, List, Optional, Tuple
from tree_sitter import Tree, Node as TSNode
from pathlib import Path

from engine.parser.import_info import ImportInfo


class ImportAnalyzer:
    """Analyze imports to understand FastAPI references - matches AST extractor behavior"""

    def __init__(self):
        self.fastapi_imports: Dict[str, str] = {}  # name -> module (e.g., "FastAPI" -> "fastapi")
        self.fastapi_aliases: Dict[str, str] = {}  # alias -> original_name (e.g., "App" -> "FastAPI")

    def analyze_imports(self, tree: Tree) -> None:
        """
        Analyze import statements to understand FastAPI references.
        Matches the logic from AST extractors (_analyze_imports method).
        """
        self.fastapi_imports.clear()
        self.fastapi_aliases.clear()

        if not tree or not tree.root_node:
            return

        # Traverse tree to find import statements
        self._traverse_for_imports(tree.root_node)

    def _traverse_for_imports(self, node: TSNode) -> None:
        """Recursively traverse tree to find import statements"""
        if node.type == "import_statement":
            self._process_import_statement(node)
        elif node.type == "import_from_statement":
            self._process_import_from_statement(node)

        # Recursively process children
        for child in node.children:
            self._traverse_for_imports(child)

    def _process_import_statement(self, node: TSNode) -> None:
        """Process: import fastapi"""
        # Find the module name (dotted_name)
        module_name = None
        alias_name = None

        for child in node.children:
            if child.type == "dotted_name":
                # Get text of dotted_name
                module_name = child.text.decode("utf-8")
            elif child.type == "aliased_import":
                # Handle: import fastapi as f
                for grandchild in child.children:
                    if grandchild.type == "dotted_name":
                        module_name = grandchild.text.decode("utf-8")
                    elif grandchild.type == "as" and len(child.children) > 2:
                        # Next sibling after "as" is the alias
                        alias_idx = list(child.children).index(grandchild) + 1
                        if alias_idx < len(child.children):
                            alias_node = child.children[alias_idx]
                            if alias_node.type == "identifier":
                                alias_name = alias_node.text.decode("utf-8")

        if module_name == "fastapi":
            self.fastapi_imports["fastapi"] = "fastapi"
            if alias_name:
                self.fastapi_aliases[alias_name] = "fastapi"

    def _process_import_from_statement(self, node: TSNode) -> None:
        """Process: from fastapi import FastAPI, APIRouter"""
        # Extract module name - look for "from" keyword followed by dotted_name
        module_name = None
        seen_from = False
        for child in node.children:
            if child.type == "from":
                seen_from = True
            elif seen_from and child.type == "dotted_name":
                module_name = child.text.decode("utf-8")
                break
            elif child.type == "dotted_name" and not module_name:
                # Fallback: just get first dotted_name
                module_name = child.text.decode("utf-8")

        if not module_name or "fastapi" not in module_name:
            return

        # Extract imported names
        # Structure can be:
        # - ['from', 'dotted_name', 'import', 'dotted_name'] - single import
        # - ['from', 'dotted_name', 'import', 'aliased_import'] - aliased import
        # - ['from', 'dotted_name', 'import', 'import_list'] - multiple imports
        import_list = None
        seen_import = False
        single_import_name = None
        aliased_import_node = None

        for child in node.children:
            if child.type == "import":
                seen_import = True
            elif child.type == "import_list":
                import_list = child
                break
            elif child.type == "aliased_import":
                # Handle: from fastapi import FastAPI as App
                aliased_import_node = child
                break
            elif seen_import and child.type == "dotted_name":
                # Single import: from fastapi import FastAPI
                single_import_name = child.text.decode("utf-8")
                break
            elif seen_import and child.type == "identifier":
                # Single import as identifier
                single_import_name = child.text.decode("utf-8")
                break

        if import_list:
            # Process each import in the list
            for import_item in import_list.children:
                self._process_import_item(import_item, module_name)
        elif aliased_import_node:
            # Process aliased import: from fastapi import FastAPI as App
            name = None
            alias = None
            for grandchild in aliased_import_node.children:
                if grandchild.type == "dotted_name":
                    name_text = grandchild.text.decode("utf-8")
                    name = name_text.split(".")[-1] if "." in name_text else name_text
                elif grandchild.type == "identifier" and not name:
                    name = grandchild.text.decode("utf-8")
                elif grandchild.type == "as":
                    # Next sibling is alias
                    alias_idx = list(aliased_import_node.children).index(grandchild) + 1
                    if alias_idx < len(aliased_import_node.children):
                        alias_node = aliased_import_node.children[alias_idx]
                        if alias_node.type == "identifier":
                            alias = alias_node.text.decode("utf-8")

            if name in ["FastAPI", "APIRouter"]:
                self.fastapi_imports[name] = module_name
                if alias:
                    self.fastapi_aliases[alias] = name
                else:
                    self.fastapi_aliases[name] = name
        elif single_import_name:
            # Single import (e.g., from fastapi import FastAPI)
            if single_import_name in ["FastAPI", "APIRouter"]:
                self.fastapi_imports[single_import_name] = module_name
                self.fastapi_aliases[single_import_name] = single_import_name

        # Also check for aliased imports in import_list (e.g., from fastapi import FastAPI as App)
        if import_list:
            for import_item in import_list.children:
                # Check if this import has an alias
                if import_item.type == "dotted_import":
                    # Look for "as" keyword and alias
                    name = None
                    alias = None
                    seen_as = False
                    for grandchild in import_item.children:
                        if grandchild.type == "identifier" or grandchild.type == "dotted_name":
                            if not name:
                                name_text = grandchild.text.decode("utf-8")
                                # If it's dotted_name, get last part
                                if grandchild.type == "dotted_name":
                                    name = name_text.split(".")[-1]
                                else:
                                    name = name_text
                        elif grandchild.type == "as":
                            seen_as = True
                        elif seen_as and grandchild.type == "identifier":
                            alias = grandchild.text.decode("utf-8")

                    if name in ["FastAPI", "APIRouter"] and alias:
                        self.fastapi_imports[name] = module_name
                        self.fastapi_aliases[alias] = name

    def _process_import_item(self, import_item: TSNode, module_name: str) -> None:
        """Process a single import item (identifier or dotted_import)"""
        name_node = None
        alias_node = None

        # Check if it's a simple identifier
        if import_item.type == "identifier":
            name_node = import_item.text.decode("utf-8")
        elif import_item.type == "dotted_import":
            # Handle: from fastapi import FastAPI
            for grandchild in import_item.children:
                if grandchild.type == "dotted_name":
                    # Last identifier in dotted_name is the actual name
                    name_parts = grandchild.text.decode("utf-8").split(".")
                    name_node = name_parts[-1] if name_parts else None
                elif grandchild.type == "identifier":
                    name_node = grandchild.text.decode("utf-8")
                elif grandchild.type == "as":
                    # Next sibling is alias
                    alias_idx = list(import_item.children).index(grandchild) + 1
                    if alias_idx < len(import_item.children):
                        alias_node = import_item.children[alias_idx]
                        if alias_node.type == "identifier":
                            alias_node = alias_node.text.decode("utf-8")

        if name_node in ["FastAPI", "APIRouter"]:
            self.fastapi_imports[name_node] = module_name
            if alias_node:
                self.fastapi_aliases[alias_node] = name_node
            else:
                # If no alias, the name itself is available
                self.fastapi_aliases[name_node] = name_node

    def is_fastapi_reference(self, name: str) -> bool:
        """
        Check if a name refers to FastAPI based on import analysis.
        Matches AST extractor _is_fastapi_reference logic.
        """
        # Direct FastAPI reference
        if name == "FastAPI" and "FastAPI" in self.fastapi_imports:
            return True

        # Aliased FastAPI reference
        if name in self.fastapi_aliases and self.fastapi_aliases[name] == "FastAPI":
            return True

        return False

    def is_apirouter_reference(self, name: str) -> bool:
        """
        Check if a name refers to APIRouter based on import analysis.
        Matches AST extractor _is_apirouter_reference logic.
        """
        # Direct APIRouter reference
        if name == "APIRouter" and "APIRouter" in self.fastapi_imports:
            return True

        # Aliased APIRouter reference
        if name in self.fastapi_aliases and self.fastapi_aliases[name] == "APIRouter":
            return True

        return False

    def is_fastapi_module_reference(self, module_name: str) -> bool:
        """Check if a module name refers to fastapi"""
        # Direct fastapi module
        if module_name == "fastapi" and "fastapi" in self.fastapi_imports:
            return True

        # Aliased fastapi module
        if module_name in self.fastapi_aliases and self.fastapi_aliases[module_name] == "fastapi":
            return True

        return False

    def extract_all_imports(self, tree: Tree) -> List[ImportInfo]:
        """
        Extract all imports from a tree, returning structured ImportInfo objects.
        This is used by ImportGraph to build the import graph.

        Returns:
            List of ImportInfo objects representing all import statements in the file
        """
        import_infos: List[ImportInfo] = []

        if not tree or not tree.root_node:
            return import_infos

        # Traverse tree to find all import statements
        self._traverse_for_all_imports(tree.root_node, import_infos)

        return import_infos

    def _traverse_for_all_imports(self, node: TSNode, import_infos: List[ImportInfo]) -> None:
        """Recursively traverse tree to find all import statements"""
        if node.type == "import_statement":
            import_info = self._extract_import_statement(node)
            if import_info:
                import_infos.append(import_info)
        elif node.type == "import_from_statement":
            import_info = self._extract_import_from_statement(node)
            if import_info:
                import_infos.append(import_info)

        # Recursively process children
        for child in node.children:
            self._traverse_for_all_imports(child, import_infos)

    def _extract_import_statement(self, node: TSNode) -> Optional[ImportInfo]:
        """
        Extract import statement: import module [as alias]
        Returns ImportInfo with import_type="import", module_name, level=0, and imports list.
        For "import module as alias", imports contains (module_name, alias).
        For "import module", imports contains (module_name, None).
        """
        module_name = None
        alias_name = None
        imports: List[Tuple[str, Optional[str]]] = []

        # Find module name and any aliases
        for child in node.children:
            if child.type == "dotted_name":
                module_name = child.text.decode("utf-8")
            elif child.type == "aliased_import":
                # Handle: import module as alias
                for grandchild in child.children:
                    if grandchild.type == "dotted_name":
                        module_name = grandchild.text.decode("utf-8")
                    elif grandchild.type == "as":
                        # Next sibling after "as" is the alias
                        alias_idx = list(child.children).index(grandchild) + 1
                        if alias_idx < len(child.children):
                            alias_node = child.children[alias_idx]
                            if alias_node.type == "identifier":
                                alias_name = alias_node.text.decode("utf-8")
                break

        if not module_name:
            return None

        # Store (module_name, alias) - alias is None if not present
        imports.append((module_name, alias_name))

        return ImportInfo(import_type="import", module_name=module_name, level=0, imports=imports)

    def _extract_import_from_statement(self, node: TSNode) -> Optional[ImportInfo]:
        """
        Extract import from statement: from [.+] module import name [as alias], ...
        Returns ImportInfo with import_type="import_from", module_name, level, and imports list
        """
        module_name: Optional[str] = None
        level = 0  # Count leading dots for relative imports
        imports: List[Tuple[str, Optional[str]]] = []

        # Count leading dots for relative imports
        # Structure: [from, relative_import, import, ...]
        # relative_import contains: [import_prefix (.), dotted_name (module_name, optional)]
        # OR: [from, dotted_name (module_name), import, ...] for absolute imports
        seen_from = False
        for i, child in enumerate(node.children):
            if child.type == "from":
                seen_from = True
            elif seen_from:
                if child.type == "relative_import":
                    # Extract level from import_prefix and module_name from dotted_name
                    for grandchild in child.children:
                        if grandchild.type == "import_prefix":
                            # Count dots in import_prefix (e.g., "." = level 1, ".." = level 2)
                            prefix_text = grandchild.text.decode("utf-8")
                            level = len(prefix_text)  # "." = 1, ".." = 2, etc.
                        elif grandchild.type == "dotted_name":
                            # Module name is inside relative_import node
                            module_name = grandchild.text.decode("utf-8")
                elif child.type == "dotted_name" and not module_name:
                    # Found module name for absolute import (only if not already found in relative_import)
                    module_name = child.text.decode("utf-8")
                    break
                elif child.type == "import":
                    # Reached "import" keyword - if we haven't found module_name yet,
                    # this is "from . import foo" (no module name)
                    break

        # Extract imported names
        # Tree-sitter structure: from, module, import, name1, ',', name2, ...
        # OR: from, module, import, import_list (name1, name2, ...)
        import_list = None
        seen_import = False
        import_items: List[TSNode] = []

        for child in node.children:
            if child.type == "import":
                seen_import = True
            elif child.type == "import_list":
                import_list = child
                break
            elif seen_import:
                # After "import", collect all import items (skip commas)
                if child.type in ["identifier", "dotted_name", "aliased_import", "dotted_import"]:
                    import_items.append(child)

        # Process imports
        if import_list:
            # Multiple imports in import_list: from module import (name1, name2, ...)
            for import_item in import_list.children:
                if import_item.type in ["identifier", "dotted_name", "aliased_import", "dotted_import"]:
                    name, alias = self._extract_import_item(import_item)
                    if name:
                        imports.append((name, alias))
        elif import_items:
            # Multiple imports as direct children: from module import name1, name2, ...
            for import_item in import_items:
                name, alias = self._extract_import_item(import_item)
                if name:
                    imports.append((name, alias))
        else:
            # No imports found - this shouldn't happen, but handle gracefully
            pass

        return ImportInfo(import_type="import_from", module_name=module_name, level=level, imports=imports)

    def _extract_import_item(self, import_item: TSNode) -> Tuple[Optional[str], Optional[str]]:
        """Extract name and alias from an import item
        Returns:
            (name, alias) tuple
        """
        if import_item.type == "identifier":
            return (import_item.text.decode("utf-8"), None)
        elif import_item.type == "dotted_name":
            name_text = import_item.text.decode("utf-8")
            # For dotted imports, use the last part as the name
            return (name_text.split(".")[-1], None)
        elif import_item.type == "aliased_import":
            return self._extract_aliased_import(import_item)
        elif import_item.type == "dotted_import":
            # Handle: from module import submodule.name
            name = None
            alias = None
            seen_as = False
            for grandchild in import_item.children:
                if grandchild.type in ["identifier", "dotted_name"]:
                    if not name:
                        name_text = grandchild.text.decode("utf-8")
                        if grandchild.type == "dotted_name":
                            name = name_text.split(".")[-1]
                        else:
                            name = name_text
                elif grandchild.type == "as":
                    seen_as = True
                elif seen_as and grandchild.type == "identifier":
                    alias = grandchild.text.decode("utf-8")
            return (name, alias)

        return (None, None)

    def _extract_aliased_import(self, aliased_import_node: TSNode) -> Tuple[Optional[str], Optional[str]]:
        """Extract name and alias from an aliased_import node"""
        name = None
        alias = None

        for grandchild in aliased_import_node.children:
            if grandchild.type == "dotted_name":
                name_text = grandchild.text.decode("utf-8")
                name = name_text.split(".")[-1] if "." in name_text else name_text
            elif grandchild.type == "identifier" and not name:
                name = grandchild.text.decode("utf-8")
            elif grandchild.type == "as":
                # Next sibling is alias
                alias_idx = list(aliased_import_node.children).index(grandchild) + 1
                if alias_idx < len(aliased_import_node.children):
                    alias_node = aliased_import_node.children[alias_idx]
                    if alias_node.type == "identifier":
                        alias = alias_node.text.decode("utf-8")

        return (name, alias)
