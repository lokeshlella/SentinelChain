"""Template rendering (Jinja2) and health endpoint."""


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "ok"
    assert body["version"]


def test_index_without_notes(client):
    html = client.get("/").get_data(as_text=True)
    assert "<h1>weather-notes</h1>" in html
    assert "Notes (0)" in html
    assert "No notes yet" in html


def test_index_lists_notes_and_escapes_html(client):
    client.post("/api/notes", json={"text": "plain note"})
    client.post("/api/notes", json={"text": "<b>bold</b>"})
    html = client.get("/").get_data(as_text=True)
    assert "Notes (2)" in html
    assert '<li id="note-1">plain note</li>' in html
    # Jinja2 autoescaping must neutralise markup coming from user input.
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
    assert "<b>bold</b>" not in html
