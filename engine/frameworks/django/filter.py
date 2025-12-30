from pathlib import Path
from loguru import logger
from engine.models import CoreGraph
from engine.frameworks.base import FrameworkFilter


class DjangoFilter(FrameworkFilter):
    """Identifies Django-specific patterns in a CoreGraph."""

    def __init__(self, project_hash: str, project_path: Path):
        self.project_hash = project_hash
        self.project_path = project_path

        # TODO: Add storage for Django components (Apps, Views, URLConfs)
        self.apps = []
        self.url_confs = []
        self.views = []
        self.services = []

    def filter(self, core_graph: CoreGraph) -> None:
        """Analyze the CoreGraph to identify Django-specific patterns."""
        logger.info("Running Django Filter...")

        # TODO: Implement detection logic
        # 1. Find INSTALLED_APPS in settings.py
        # 2. Find urlpatterns in urls.py
        # 3. Find Views (FBV and CBV)
        pass
