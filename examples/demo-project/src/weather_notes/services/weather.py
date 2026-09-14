"""Weather lookup built on the ``requests`` library.

``requests`` is the primary deliberately vulnerable dependency of this demo
project (see README.md). The client is small on purpose: one GET, JSON
decoding and a defensive summary so callers never see a raw exception.
"""

from __future__ import annotations

from typing import Any

import requests


class WeatherClient:
    """Fetch a JSON weather document and reduce it to a small summary."""

    #: Open-Meteo style endpoint; overridable through the WEATHER_URL environment variable.
    DEFAULT_URL = "https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&current_weather=true"

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self.url = url
        self.timeout = timeout

    def fetch(self) -> dict[str, Any]:
        """Perform the HTTP request and return the decoded JSON body."""
        response = requests.get(self.url, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("weather endpoint did not return a JSON object")
        return payload

    def current_summary(self) -> dict[str, Any]:
        """Return ``{"ok": True, "temperature": ..., "windspeed": ...}`` or an error summary."""
        try:
            payload = self.fetch()
        except (requests.RequestException, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        current = payload.get("current_weather") or {}
        return {
            "ok": True,
            "temperature": current.get("temperature"),
            "windspeed": current.get("windspeed"),
            "source": self.url,
        }
