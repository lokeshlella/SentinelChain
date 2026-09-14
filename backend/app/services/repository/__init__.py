"""Repository ingestion stage: providers (GitHub, local), analyser and service."""

from app.services.repository.analyzer import ComponentInfo, RepositoryAnalyzer, RepositoryProfile
from app.services.repository.base import FetchedRepository, RepositoryProvider, RepositorySource
from app.services.repository.github_provider import GitHubRepositoryProvider, parse_github_remote, parse_github_url
from app.services.repository.ignore import IGNORED_DIR_NAMES, copytree_ignore, should_analyze_dir
from app.services.repository.local_provider import LocalRepositoryProvider
from app.services.repository.service import RepositoryService

__all__ = [
    "ComponentInfo",
    "FetchedRepository",
    "GitHubRepositoryProvider",
    "IGNORED_DIR_NAMES",
    "LocalRepositoryProvider",
    "RepositoryAnalyzer",
    "RepositoryProfile",
    "RepositoryProvider",
    "RepositoryService",
    "RepositorySource",
    "copytree_ignore",
    "parse_github_remote",
    "parse_github_url",
    "should_analyze_dir",
]
