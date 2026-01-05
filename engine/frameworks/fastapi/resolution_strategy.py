"""FastAPI-specific resolution strategy."""

from typing import Optional, List

from engine.binder.resolution_strategy import ResolutionStrategy
from engine.binder import SymbolIndex
from engine.models import BaseNode, NodeType


class FastAPIResolutionStrategy(ResolutionStrategy):
    """FastAPI-specific resolution strategy for apps, routers, and services."""

    def get_resolution_types(self) -> List[NodeType]:
        """Return FastAPI node types: application, router, service_class."""
        return [NodeType.application, NodeType.router, NodeType.service_class]

    def find_local_instances(self, symbol_index: SymbolIndex, file_rel: str, identifier: str) -> Optional[BaseNode]:
        """Find local FastAPI instances: app, router, or service."""
        return (
            symbol_index.find_app(file_rel, identifier)
            or symbol_index.find_router(file_rel, identifier)
            or symbol_index.find_service_instance(file_rel, identifier)
        )

    def find_by_module(self, symbol_index: SymbolIndex, module_path: str, identifier: str) -> Optional[BaseNode]:
        """Find FastAPI component by module path: app or router."""
        return symbol_index.find_app_by_module(module_path, identifier) or symbol_index.find_router_by_module(
            module_path, identifier
        )

    def find_by_file(self, symbol_index: SymbolIndex, file_rel: str, identifier: str) -> Optional[BaseNode]:
        """Find FastAPI component by file path: app, router, service instance, or service class."""
        return (
            symbol_index.find_app(file_rel, identifier)
            or symbol_index.find_router(file_rel, identifier)
            or symbol_index.find_service_instance(file_rel, identifier)
            or symbol_index.find_service_class(identifier)
        )

    def find_attribute_by_module(
        self, symbol_index: SymbolIndex, module_path: str, attribute_name: str
    ) -> Optional[BaseNode]:
        """Find FastAPI component by module path for attribute access: router or app."""
        return symbol_index.find_router_by_module(module_path, attribute_name) or symbol_index.find_app_by_module(
            module_path, attribute_name
        )

    def find_attribute_by_file(
        self, symbol_index: SymbolIndex, file_rel: str, attribute_name: str
    ) -> Optional[BaseNode]:
        """Find FastAPI component by file path for attribute access: router, app, or service instance."""
        return (
            symbol_index.find_router(file_rel, attribute_name)
            or symbol_index.find_app(file_rel, attribute_name)
            or symbol_index.find_service_instance(file_rel, attribute_name)
        )
