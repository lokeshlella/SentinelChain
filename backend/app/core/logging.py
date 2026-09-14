"""Structured, stage-prefixed logging.

Every major workflow stage logs through a stage logger so that the log stream
reads like:

    [Repository] Repository cloned
    [Dependencies] 42 dependencies extracted
    [Vulnerability] 3 vulnerable dependencies found
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers = [handler]
    # Quieten noisy libraries.
    for noisy in ("httpx", "httpcore", "urllib3", "docker", "neo4j", "git"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True


class StageLoggerAdapter(logging.LoggerAdapter):
    """Prefixes every message with the workflow stage, e.g. ``[Sandbox] ...``."""

    def process(self, msg, kwargs):
        return f"[{self.extra['stage']}] {msg}", kwargs


def get_stage_logger(stage: str) -> StageLoggerAdapter:
    """Return a logger for a workflow stage (Repository, Dependencies, Vulnerability, ...)."""
    return StageLoggerAdapter(logging.getLogger(f"sentinel.{stage.lower()}"), {"stage": stage})
