"""
Deepwave Engine - Pure analysis library for codebase analysis.

This package contains all the analysis logic extracted from the FastAPI backend.
It has no dependencies on FastAPI, databases, or external services.
"""

from .analyze import analyze_repo

__all__ = ["analyze_repo"]
