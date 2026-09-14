"""Application configuration loaded from environment variables / .env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# The repository root is two levels above backend/app/core/config.py -> backend/
BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    """All runtime configuration for Sentinel Chain.

    Every value can be overridden with an environment variable of the same
    name (case-insensitive). A ``.env`` file in the project root or the
    backend directory is read automatically.
    """

    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_ROOT / ".env"), str(BACKEND_DIR / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application -------------------------------------------------------
    app_name: str = "Sentinel Chain"
    app_env: str = Field(default="development", description="development|test|production")
    log_level: str = "INFO"
    api_prefix: str = "/api"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
    api_key: str | None = Field(
        default=None,
        description="When set, every /api request except the health endpoints must carry it in the "
        "X-API-Key header (or ?api_key=). Leave empty for a local single-user setup.",
    )

    # --- PostgreSQL --------------------------------------------------------
    database_url: str = "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinelchain"

    # --- Neo4j -------------------------------------------------------------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "sentinelchain"
    neo4j_database: str = "neo4j"

    # --- Ollama (local LLM) ------------------------------------------------
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = Field(
        default="llama3.2:3b",
        description="Any model available in the local Ollama instance (see `ollama list`).",
    )
    ollama_timeout: int = Field(default=180, description="Seconds to wait for a single LLM response.")
    ollama_num_ctx: int = Field(default=8192, description="Context window requested from Ollama.")
    ollama_temperature: float = 0.1
    llm_max_retries: int = Field(default=2, description="Retries with a correction prompt when output is malformed.")
    ai_max_findings_per_analysis: int = Field(
        default=5,
        description="Upper bound on findings analysed by the LLM during one analysis run; "
        "remaining findings can be analysed on demand.",
    )

    # --- Background jobs ---------------------------------------------------
    job_heartbeat_timeout: int = Field(
        default=900,
        description="Seconds without a heartbeat after which a RUNNING/PENDING job (analysis, validation, "
        "remediation, on-demand AI, ingestion) is considered dead and marked FAILED. Raised automatically "
        "to cover DOCKER_TIMEOUT and the LLM retry budget.",
    )

    # --- GitHub ------------------------------------------------------------
    github_token: str | None = None

    # --- Workspace / sandbox ----------------------------------------------
    repository_workspace: str = Field(
        default=str(PROJECT_ROOT / "workspace"),
        description="Directory where clones, working copies, logs and reports are stored.",
    )
    docker_timeout: int = Field(default=600, description="Seconds before a sandbox container is killed.")
    docker_python_image: str = "python:3.12-slim"
    docker_node_image: str = "node:20-slim"
    docker_memory_limit: str = "2g"
    docker_cpu_limit: float = 2.0
    docker_sandbox_user: str = Field(
        default="65534:65534",
        description="uid:gid the sandbox steps run as (never root). The workspace tmpfs is owned by this user.",
    )
    docker_sandbox_network: str = Field(
        default="bridge",
        description="Docker network mode for the sandbox: 'bridge' (package registries reachable — needed for pip/npm "
        "install) or 'none' for repositories with vendored dependencies.",
    )
    docker_read_only_rootfs: bool = Field(default=True, description="Mount the sandbox root filesystem read-only.")
    docker_workspace_tmpfs_size: str = Field(default="1g", description="Size of the in-memory /workspace tmpfs of the sandbox.")

    # --- External services -------------------------------------------------
    osv_api_url: str = "https://api.osv.dev/v1"
    osv_timeout: int = 30
    registry_timeout: int = 20
    git_clone_timeout: int = 300

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def workspace_path(self) -> Path:
        path = Path(self.repository_workspace).expanduser()
        if not path.is_absolute():
            # Relative paths are anchored to the project root, not the process CWD.
            path = PROJECT_ROOT / path
        path = path.resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache
def get_settings() -> Settings:
    return Settings()
