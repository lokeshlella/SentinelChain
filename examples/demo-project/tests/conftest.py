"""Shared fixtures.

Tests never reach the network: the weather URL points at a reserved ``.invalid``
host and ``requests.get`` is patched in every test that touches the weather code.
"""

from __future__ import annotations

import pytest

from weather_notes import create_app

FAKE_WEATHER_URL = "http://weather.invalid/forecast"


@pytest.fixture()
def app():
    """A fresh application (and therefore a fresh, empty note store) per test."""
    return create_app({"TESTING": True, "WEATHER_URL": FAKE_WEATHER_URL, "WEATHER_TIMEOUT": 1})


@pytest.fixture()
def client(app):
    return app.test_client()
