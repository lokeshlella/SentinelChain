"""Notes API behaviour through Flask's test client."""


def test_list_is_empty_initially(client):
    response = client.get("/api/notes")
    assert response.status_code == 200
    assert response.get_json() == []


def test_create_and_fetch_note(client):
    created = client.post("/api/notes", json={"text": "  bring an umbrella  "})
    assert created.status_code == 201
    note = created.get_json()
    assert note == {"id": 1, "text": "bring an umbrella"}

    fetched = client.get("/api/notes/1")
    assert fetched.status_code == 200
    assert fetched.get_json() == note


def test_ids_increase_and_listing_is_ordered(client):
    for text in ("first", "second", "third"):
        client.post("/api/notes", json={"text": text})
    listed = client.get("/api/notes").get_json()
    assert [n["id"] for n in listed] == [1, 2, 3]
    assert [n["text"] for n in listed] == ["first", "second", "third"]


def test_delete_note(client):
    client.post("/api/notes", json={"text": "temporary"})
    assert client.delete("/api/notes/1").status_code == 204
    assert client.get("/api/notes/1").status_code == 404
    assert client.delete("/api/notes/1").status_code == 404


def test_rejects_invalid_bodies(client):
    assert client.post("/api/notes", json={"text": ""}).status_code == 400
    assert client.post("/api/notes", json={"text": 42}).status_code == 400
    assert client.post("/api/notes", json=["not", "an", "object"]).status_code == 400
    assert client.post("/api/notes", data="not json", content_type="text/plain").status_code == 400
    assert client.post("/api/notes", json={"text": "x" * 501}).status_code == 400


def test_unknown_note_is_404(client):
    assert client.get("/api/notes/999").status_code == 404


def test_each_app_instance_has_its_own_store(app):
    from weather_notes import create_app

    app.test_client().post("/api/notes", json={"text": "only here"})
    other = create_app({"TESTING": True})
    assert other.test_client().get("/api/notes").get_json() == []
    assert len(app.test_client().get("/api/notes").get_json()) == 1
