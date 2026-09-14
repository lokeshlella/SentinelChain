"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.db.base import Base
from app.models.analysis import Analysis
from app.models.component import Component
from app.models.dependency import Dependency, DependencyRelation
from app.models.finding import Finding
from app.models.pull_request import PullRequest
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.models.validation import Validation
from app.models.vulnerability import Vulnerability

__all__ = [
    "Base",
    "Analysis",
    "Component",
    "Dependency",
    "DependencyRelation",
    "Finding",
    "PullRequest",
    "Remediation",
    "Repository",
    "Validation",
    "Vulnerability",
]
