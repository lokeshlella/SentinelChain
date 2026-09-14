from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_each_service():
    with (
        patch("app.api.routes.health.check_database", return_value=(True, "pg")),
        patch("app.api.routes.health.check_neo4j", return_value=(False, "down")),
        patch("app.api.routes.health._check_ollama", return_value=(False, "down")),
        patch("app.api.routes.health._check_docker", return_value=(False, "down")),
        patch("app.api.routes.health._check_github", return_value=(False, "no token")),
    ):
        client = TestClient(app)
        response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"  # PostgreSQL is the only mandatory service
    assert {s["name"] for s in body["services"]} == {"postgresql", "neo4j", "ollama", "docker", "github"}


def test_health_degraded_without_database():
    with (
        patch("app.api.routes.health.check_database", return_value=(False, "refused")),
        patch("app.api.routes.health.check_neo4j", return_value=(True, "ok")),
        patch("app.api.routes.health._check_ollama", return_value=(True, "ok")),
        patch("app.api.routes.health._check_docker", return_value=(True, "ok")),
        patch("app.api.routes.health._check_github", return_value=(True, "ok")),
    ):
        response = TestClient(app).get("/api/health")
    assert response.json()["status"] == "degraded"


def test_models_create_on_sqlite(engine):
    from sqlalchemy import inspect

    tables = set(inspect(engine).get_table_names())
    assert {"repositories", "dependencies", "vulnerabilities", "analyses", "findings",
            "remediations", "validations", "pull_requests", "components", "dependency_relations"} <= tables


def test_interrupted_jobs_are_marked_failed_on_startup(engine, db, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    from app import main
    from app.models import Analysis, Repository

    repo = Repository(name="r", source_url="/tmp/r", source_type="local")
    db.add(repo)
    db.flush()
    db.add(Analysis(repository_id=repo.repository_id, status="RUNNING"))
    db.commit()
    monkeypatch.setattr("app.db.session.get_session_factory", lambda: sessionmaker(bind=engine, expire_on_commit=False))
    main.mark_interrupted_jobs()
    db.expire_all()
    analysis = db.query(Analysis).one()
    assert analysis.status == "FAILED" and "restart" in analysis.error_message
