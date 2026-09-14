from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import deps
from app.api.serializers import finding_summary
from app.core.exceptions import NotFoundError
from app.models import Dependency, DependencyRelation, Finding
from app.schemas.entities import DependencyDetail, RelationOut, VulnerabilitySummary
from app.services.analysis.usage import SourceUsageAnalyzer
from app.services.knowledge_graph.service import KnowledgeGraphService

router = APIRouter(prefix="/dependencies", tags=["dependencies"])


def _get(db: Session, dependency_id: int) -> Dependency:
    dep = db.get(Dependency, dependency_id)
    if dep is None:
        raise NotFoundError(f"Dependency {dependency_id} not found")
    return dep


def _relation_out(rel: DependencyRelation, parent: Dependency, child: Dependency) -> RelationOut:
    return RelationOut(
        relation_id=rel.relation_id,
        parent_dependency_id=rel.parent_dependency_id,
        child_dependency_id=rel.child_dependency_id,
        relation_type=rel.relation_type,
        parent=f"{parent.package_name}@{parent.version or '?'}",
        child=f"{child.package_name}@{child.version or '?'}",
    )


@router.get("/{dependency_id}", response_model=DependencyDetail)
def get_dependency(dependency_id: int, db: Session = deps.DbDep):
    dep = _get(db, dependency_id)
    out = DependencyDetail.model_validate(dep)
    findings = db.scalars(select(Finding).where(Finding.dependency_id == dependency_id).order_by(Finding.finding_id)).all()
    out.findings = [finding_summary(f) for f in findings]
    seen: set[int] = set()
    for f in findings:
        if f.vulnerability_id not in seen:
            seen.add(f.vulnerability_id)
            out.vulnerabilities.append(VulnerabilitySummary.model_validate(f.vulnerability))
    for rel in db.scalars(select(DependencyRelation).where(DependencyRelation.parent_dependency_id == dependency_id)):
        child = db.get(Dependency, rel.child_dependency_id)
        if child:
            out.depends_on.append(_relation_out(rel, dep, child))
    for rel in db.scalars(select(DependencyRelation).where(DependencyRelation.child_dependency_id == dependency_id)):
        parent = db.get(Dependency, rel.parent_dependency_id)
        if parent:
            out.depended_on_by.append(_relation_out(rel, parent, dep))
    return out


@router.get("/{dependency_id}/graph", summary="Knowledge-graph view of one dependency")
def dependency_graph(
    dependency_id: int, db: Session = deps.DbDep, graph: KnowledgeGraphService = Depends(deps.get_graph_service)
) -> dict:
    dep = _get(db, dependency_id)
    if not graph.available():
        return {"available": False, "message": "Knowledge graph unavailable: Neo4j could not be reached"}
    return {
        "available": True,
        "components_using": graph.components_using_dependency(dep),
        "related": graph.related_dependencies(dep),
        "vulnerabilities": graph.vulnerabilities_for_dependency(dep),
        "paths": graph.dependency_paths(dep),
    }


@router.get("/{dependency_id}/usage", summary="Source files referencing the dependency (live scan)")
def dependency_usage(dependency_id: int, db: Session = deps.DbDep) -> dict:
    dep = _get(db, dependency_id)
    repository = dep.repository
    path = Path(repository.local_path or "")
    if not path.exists():
        return {"available": False, "message": "Working copy not available; re-run the analysis with refresh=true"}
    evidence = SourceUsageAnalyzer().find_usage(path, dep.package_name, dep.ecosystem, [c.path for c in repository.components])
    return {"available": True, **evidence.to_dict()}
