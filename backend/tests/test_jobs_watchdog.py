"""Audit F-06: jobs that died must not stay RUNNING/PENDING forever (no restart required)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.config import Settings
from app.db.base import utcnow
from app.models import Analysis, Dependency, Finding, Remediation, Repository, Validation, Vulnerability
from app.models.enums import AIStatus, AnalysisStatus, RemediationStatus, RepositoryStatus, ValidationStatus
from app.services.jobs import RESTART_REASON, expire_if_stale, heartbeat_timeout, is_stale, sweep_stale_jobs


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, job_heartbeat_timeout=600, docker_timeout=100, ollama_timeout=30, llm_max_retries=1)


def stale_time(seconds: int = 3600):
    return utcnow() - timedelta(seconds=seconds)


@pytest.fixture
def rows(db):
    repo = Repository(name="r", source_url="/tmp/r", source_type="local", status=RepositoryStatus.READY)
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status=AnalysisStatus.RUNNING, started_at=stale_time(),
                        heartbeat_at=stale_time(), stages={"repository": "OK", "ai": "RUNNING", "usage": "PENDING"})
    db.add(analysis)
    db.flush()
    dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="p", version="1", ecosystem="PyPI",
                     direct_or_transitive="unknown", source_file="requirements.txt", vulnerability_status="VULNERABLE")
    vuln = Vulnerability(identifier="GHSA-x", source="osv", severity="LOW")
    db.add_all([dep, vuln])
    db.flush()
    finding = Finding(analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id,
                      ai_status=AIStatus.RUNNING, ai_updated_at=stale_time())
    db.add(finding)
    db.flush()
    remediation = Remediation(finding_id=finding.finding_id, status=RemediationStatus.PENDING, heartbeat_at=stale_time())
    db.add(remediation)
    db.flush()
    validation = Validation(remediation_id=remediation.remediation_id, status=ValidationStatus.RUNNING, heartbeat_at=stale_time())
    db.add(validation)
    db.commit()
    return {"repo": repo, "analysis": analysis, "finding": finding, "remediation": remediation, "validation": validation}


def test_heartbeat_timeout_covers_the_longest_single_step(settings):
    assert heartbeat_timeout(settings) == 600  # configured value dominates here
    settings.docker_timeout = 1200
    assert heartbeat_timeout(settings) == 1320  # a sandbox run may legitimately be silent that long
    settings.docker_timeout = 100
    settings.ollama_timeout = 400
    settings.llm_max_retries = 2
    assert heartbeat_timeout(settings) == 400 * 3 + 60


def test_is_stale_rules():
    assert is_stale(None, 10)
    assert is_stale(stale_time(20), 10)
    assert not is_stale(utcnow(), 10)


def test_expire_if_stale_marks_each_job_kind_failed(db, rows, settings):
    assert expire_if_stale(db, rows["analysis"], settings)
    assert rows["analysis"].status == AnalysisStatus.FAILED and "stopped reporting progress" in rows["analysis"].error_message
    assert rows["analysis"].stages == {"repository": "OK", "ai": "FAILED", "usage": "SKIPPED"}
    assert expire_if_stale(db, rows["finding"], settings) and rows["finding"].ai_status == AIStatus.FAILED
    assert expire_if_stale(db, rows["remediation"], settings) and rows["remediation"].status == RemediationStatus.FAILED
    rows["remediation"].status = RemediationStatus.VALIDATING
    assert expire_if_stale(db, rows["validation"], settings)
    assert rows["validation"].status == ValidationStatus.FAILED and rows["remediation"].status == RemediationStatus.VALIDATION_FAILED


def test_fresh_heartbeats_are_left_alone(db, rows, settings):
    rows["analysis"].heartbeat_at = utcnow()
    rows["finding"].ai_updated_at = utcnow()
    db.commit()
    assert not expire_if_stale(db, rows["analysis"], settings) and rows["analysis"].status == AnalysisStatus.RUNNING
    assert not expire_if_stale(db, rows["finding"], settings) and rows["finding"].ai_status == AIStatus.RUNNING
    assert not expire_if_stale(db, rows["repo"], settings)  # READY rows are never touched


def test_pending_repository_ingestion_expires_by_updated_at(db, rows, settings):
    rows["repo"].status = RepositoryStatus.PENDING
    db.commit()
    assert not expire_if_stale(db, rows["repo"], settings)  # just updated
    rows["repo"].updated_at = stale_time()  # an explicit value wins over the onupdate default
    db.commit()
    assert expire_if_stale(db, rows["repo"], settings)
    assert rows["repo"].status == RepositoryStatus.FAILED and "stopped reporting progress" in rows["repo"].error_message


def test_sweep_everything_marks_all_in_progress_rows_on_restart(db, rows, settings):
    rows["analysis"].heartbeat_at = utcnow()  # fresh, but the process restarted → dead anyway
    db.commit()
    counts = sweep_stale_jobs(db, settings, everything=True)
    assert counts == {"analyses": 1, "validations": 1, "remediations": 1, "findings": 1, "repositories": 0}
    assert rows["analysis"].error_message == RESTART_REASON and rows["validation"].status == ValidationStatus.FAILED
