"""weather-notes: a tiny Flask service used as the Sentinel Chain demo application.

The application keeps a few notes in memory and can show a compact weather
summary fetched from a JSON endpoint. It intentionally depends on *vulnerable*
(but fully functional) versions of ``requests`` and ``Jinja2`` so that the
Sentinel Chain workflow has something real to find, remediate and validate.
It contains no malicious code.
"""

from __future__ import annotations

import os

from flask import Flask, render_template

from weather_notes.routes.notes import NoteStore, get_store, notes_bp
from weather_notes.services.weather import WeatherClient

__version__ = "0.1.0"


def create_app(config: dict | None = None) -> Flask:
    """Application factory.

    Configuration comes from the environment (``WEATHER_URL``, ``WEATHER_TIMEOUT``)
    and can be overridden with ``config``; the tests pass a reserved ``.invalid``
    URL and mock ``requests``, so the weather endpoint is never called from tests.
    """
    app = Flask(__name__)
    app.config["WEATHER_URL"] = os.environ.get("WEATHER_URL", WeatherClient.DEFAULT_URL)
    app.config["WEATHER_TIMEOUT"] = float(os.environ.get("WEATHER_TIMEOUT", "5"))
    if config:
        app.config.update(config)

    # One in-memory note store per application instance (fresh for every test).
    app.extensions["note_store"] = NoteStore()
    app.register_blueprint(notes_bp)

    @app.get("/")
    def index() -> str:
        """Render the landing page (Jinja2 template) listing the current notes."""
        return render_template("index.html", notes=get_store().all(), version=__version__)

    @app.get("/weather")
    def weather() -> tuple[dict, int]:
        """Return a compact weather summary fetched from the configured endpoint."""
        client = WeatherClient(app.config["WEATHER_URL"], timeout=app.config["WEATHER_TIMEOUT"])
        summary = client.current_summary()
        status = 200 if summary["ok"] else 502
        return summary, status

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    return app
