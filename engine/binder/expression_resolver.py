"""General-purpose expression resolver using Binder.

This component is framework-agnostic and can be used by any framework-specific
discoverer (FastAPI, Django, Flask, etc.) to resolve expressions to nodes.
"""

from pathlib import Path
from typing import Optional
from tree_sitter import Node as TSNode

from engine.models import BaseNode, ApplicationNode, RouterNode, ServiceClassNode
from .binder_treesitter import BinderTreeSitter


class ExpressionResolver:
    """
    Resolves any expression to a known node using Binder.

    This is a framework-agnostic component that works for any framework
    (FastAPI, Django, Flask, Express.js, etc.). It doesn't know about
    framework-specific patterns - it just resolves expressions to nodes.

    Handles:
    - Identifiers: user_router
    - Attributes: architecture.router
    - Aliased attributes: arch.router (where arch = architecture)
    - Variable references: my_router (where my_router = user_router)
    - Complex expressions: get_router(), routers[0] (with limitations)
    """

    def __init__(self, binder: BinderTreeSitter):
        """
        Initialize the expression resolver.

        Args:
            binder: Binder instance for resolving identifiers and attributes
        """
        self.binder = binder

    def resolve(self, expr_node: TSNode, file_path: Path) -> Optional[BaseNode]:
        """
        Resolve any expression to a node.

        Args:
            expr_node: Tree-sitter node (identifier, attribute, call, etc.)
            file_path: File containing the expression

        Returns:
            Resolved node (ApplicationNode, RouterNode, ServiceClassNode, etc.) or None
        """
        # Identifier: user_router
        if expr_node.type == "identifier":
            return self.binder.bind_name("", file_path, expr_node)

        # Attribute: architecture.router, arch.router
        elif expr_node.type == "attribute":
            return self.binder.bind_attribute("", file_path, expr_node)

        # Call: get_router() - resolve factory functions
        elif expr_node.type == "call":
            function_node = expr_node.child_by_field_name("function")
            if not function_node or function_node.type != "identifier":
                return None

            func_name = function_node.text.decode("utf-8")
            file_rel = str(file_path.relative_to(self.binder.project_path))

            # Check if this is a known router factory function
            router = self.binder.symbol_index.resolve_router_factory(file_rel, func_name)
            if router:
                return router

            return None

        # Subscription: routers[0] - try to resolve if possible
        elif expr_node.type == "subscription":
            # For now, return None (could add heuristics later)
            return None

        # General expression - use bind_expr
        else:
            return self.binder.bind_expr(file_path, expr_node)

    def resolve_to_router(self, expr_node: TSNode, file_path: Path) -> Optional[RouterNode]:
        """
        Resolve expression specifically to a RouterNode.

        Args:
            expr_node: Tree-sitter node to resolve
            file_path: File containing the expression

        Returns:
            RouterNode if resolved, None otherwise
        """
        resolved = self.resolve(expr_node, file_path)
        if isinstance(resolved, RouterNode):
            return resolved
        return None

    def resolve_to_application(self, expr_node: TSNode, file_path: Path) -> Optional[ApplicationNode]:
        """
        Resolve expression specifically to an ApplicationNode.

        Args:
            expr_node: Tree-sitter node to resolve
            file_path: File containing the expression

        Returns:
            ApplicationNode if resolved, None otherwise
        """
        resolved = self.resolve(expr_node, file_path)
        if isinstance(resolved, ApplicationNode):
            return resolved
        return None

    def resolve_to_service(self, expr_node: TSNode, file_path: Path) -> Optional[ServiceClassNode]:
        """
        Resolve expression specifically to a ServiceClassNode.

        Args:
            expr_node: Tree-sitter node to resolve
            file_path: File containing the expression

        Returns:
            ServiceClassNode if resolved, None otherwise
        """
        resolved = self.resolve(expr_node, file_path)
        if isinstance(resolved, ServiceClassNode):
            return resolved
        return None
