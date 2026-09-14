"""Dependency extraction (PyPI requirements files, npm manifests and lock files)."""

from app.services.dependencies.base import (
    DependencyExtractor,
    ExtractedDependency,
    ExtractedRelation,
    ExtractionResult,
)
from app.services.dependencies.javascript_extractor import JavaScriptDependencyExtractor
from app.services.dependencies.python_extractor import PythonDependencyExtractor
from app.services.dependencies.service import DependencyService, get_extractors

__all__ = [
    "DependencyExtractor",
    "ExtractedDependency",
    "ExtractedRelation",
    "ExtractionResult",
    "JavaScriptDependencyExtractor",
    "PythonDependencyExtractor",
    "DependencyService",
    "get_extractors",
]
