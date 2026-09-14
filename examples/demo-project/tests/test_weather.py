"""Weather endpoint tests with ``requests`` fully mocked (no network access)."""

from unittest.mock import MagicMock, patch

import requests

from weather_notes.services.weather import WeatherClient

PATCH_TARGET = "weather_notes.services.weather.requests.get"


def _fake_response(payload, status=200):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(f"{status} error")
    else:
        response.raise_for_status.return_value = None
    return response


def test_current_summary_reduces_payload():
    payload = {"current_weather": {"temperature": 18.4, "windspeed": 7.2, "winddirection": 180}}
    with patch(PATCH_TARGET, return_value=_fake_response(payload)) as mocked:
        summary = WeatherClient("http://weather.invalid/forecast", timeout=2).current_summary()
    mocked.assert_called_once_with("http://weather.invalid/forecast", timeout=2)
    assert summary == {
        "ok": True,
        "temperature": 18.4,
        "windspeed": 7.2,
        "source": "http://weather.invalid/forecast",
    }


def test_missing_current_weather_yields_none_values():
    with patch(PATCH_TARGET, return_value=_fake_response({"unexpected": True})):
        summary = WeatherClient("http://weather.invalid/forecast").current_summary()
    assert summary["ok"] is True
    assert summary["temperature"] is None
    assert summary["windspeed"] is None


def test_http_error_is_reported_not_raised():
    with patch(PATCH_TARGET, return_value=_fake_response({}, status=503)):
        summary = WeatherClient("http://weather.invalid/forecast").current_summary()
    assert summary["ok"] is False
    assert "503" in summary["error"]


def test_connection_error_is_reported_not_raised():
    with patch(PATCH_TARGET, side_effect=requests.ConnectionError("boom")):
        summary = WeatherClient("http://weather.invalid/forecast").current_summary()
    assert summary == {"ok": False, "error": "boom"}


def test_non_object_json_is_rejected():
    with patch(PATCH_TARGET, return_value=_fake_response(["a", "list"])):
        summary = WeatherClient("http://weather.invalid/forecast").current_summary()
    assert summary["ok"] is False
    assert "JSON object" in summary["error"]


def test_weather_route_uses_configured_url(client, app):
    payload = {"current_weather": {"temperature": -3.0, "windspeed": 12.5}}
    with patch(PATCH_TARGET, return_value=_fake_response(payload)) as mocked:
        response = client.get("/weather")
    assert response.status_code == 200
    body = response.get_json()
    assert body["temperature"] == -3.0
    assert body["source"] == app.config["WEATHER_URL"]
    mocked.assert_called_once_with(app.config["WEATHER_URL"], timeout=app.config["WEATHER_TIMEOUT"])


def test_weather_route_returns_502_on_failure(client):
    with patch(PATCH_TARGET, side_effect=requests.Timeout("too slow")):
        response = client.get("/weather")
    assert response.status_code == 502
    assert response.get_json() == {"ok": False, "error": "too slow"}
