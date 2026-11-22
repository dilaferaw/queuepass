"""End-to-end HTTP tests for the ``/api/v1/events`` endpoints."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from httpx import AsyncClient


async def test_create_event_201_with_nested(
    client: AsyncClient,
    auth_headers: dict[str, str],
    registered_user: dict[str, object],
    sample_event_payload: dict[str, object],
) -> None:
    resp = await client.post(
        "/api/v1/events",
        json=sample_event_payload,
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()

    assert body["organizer_id"] == registered_user["id"]
    assert len(body["ticket_types"]) == 2
    assert len(body["sections"]) == 2

    tt_by_name = {tt["name"]: tt["id"] for tt in body["ticket_types"]}
    section_by_name = {s["name"]: s for s in body["sections"]}

    assert section_by_name["Floor"]["ticket_type_id"] == tt_by_name["Standard"]
    assert section_by_name["Balcony"]["ticket_type_id"] == tt_by_name["VIP"]
    assert len(section_by_name["Floor"]["seats"]) == 3
    assert len(section_by_name["Balcony"]["seats"]) == 3


async def test_create_event_unauthenticated_401(
    client: AsyncClient,
    sample_event_payload: dict[str, object],
) -> None:
    resp = await client.post("/api/v1/events", json=sample_event_payload)
    assert resp.status_code == 401


async def test_create_event_duplicate_seat_409_and_rolls_back(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    bad = deepcopy(sample_event_payload)
    bad["name"] = "Should Never Persist"
    bad["sections"][0]["seats"].append({"row_label": "A", "seat_number": 1})  # type: ignore[index]

    resp = await client.post("/api/v1/events", json=bad, headers=auth_headers)
    assert resp.status_code == 409, resp.text

    list_resp = await client.get("/api/v1/events")
    assert list_resp.status_code == 200
    names = [ev["name"] for ev in list_resp.json()]
    assert "Should Never Persist" not in names


async def test_create_event_duplicate_section_name_409(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    bad = deepcopy(sample_event_payload)
    bad["sections"][1]["name"] = "Floor"  # type: ignore[index]

    resp = await client.post("/api/v1/events", json=bad, headers=auth_headers)
    assert resp.status_code == 409, resp.text


async def test_create_event_starts_after_ends_422(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    bad = deepcopy(sample_event_payload)
    starts = datetime.now(UTC) + timedelta(days=7)
    bad["starts_at"] = starts.isoformat()
    bad["ends_at"] = (starts - timedelta(hours=1)).isoformat()

    resp = await client.post("/api/v1/events", json=bad, headers=auth_headers)
    assert resp.status_code == 422, resp.text


async def test_create_event_starts_in_past_400(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    bad = deepcopy(sample_event_payload)
    past = datetime.now(UTC) - timedelta(days=2)
    bad["starts_at"] = past.isoformat()
    bad["ends_at"] = (past + timedelta(hours=2)).isoformat()

    resp = await client.post("/api/v1/events", json=bad, headers=auth_headers)
    assert resp.status_code == 400, resp.text


async def test_get_event_404(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/events/{uuid4()}")
    assert resp.status_code == 404


async def test_get_event_returns_nested_structure(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    create_resp = await client.post(
        "/api/v1/events",
        json=sample_event_payload,
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    event_id = create_resp.json()["id"]

    get_resp = await client.get(f"/api/v1/events/{event_id}")
    assert get_resp.status_code == 200, get_resp.text
    detail = get_resp.json()

    assert detail["id"] == event_id
    assert detail["name"] == sample_event_payload["name"]
    assert detail["description"] == sample_event_payload["description"]
    assert detail["venue_address"] == sample_event_payload["venue_address"]
    assert "created_at" in detail
    assert len(detail["ticket_types"]) == 2
    assert len(detail["sections"]) == 2
    for section in detail["sections"]:
        assert len(section["seats"]) == 3
        for seat in section["seats"]:
            assert {"id", "row_label", "seat_number"} <= set(seat.keys())


async def test_list_events_returns_created(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    create_resp = await client.post(
        "/api/v1/events",
        json=sample_event_payload,
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    event_id = create_resp.json()["id"]

    list_resp = await client.get("/api/v1/events")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) == 1
    assert items[0]["id"] == event_id
    assert items[0]["name"] == sample_event_payload["name"]
    assert "sections" not in items[0]
    assert "ticket_types" not in items[0]


async def test_list_events_pagination(
    client: AsyncClient,
    auth_headers: dict[str, str],
    sample_event_payload: dict[str, object],
) -> None:
    created_ids: list[str] = []
    for i in range(5):
        payload = deepcopy(sample_event_payload)
        payload["name"] = f"Event {i}"
        resp = await client.post("/api/v1/events", json=payload, headers=auth_headers)
        assert resp.status_code == 201, resp.text
        created_ids.append(resp.json()["id"])

    page_resp = await client.get("/api/v1/events?limit=2&offset=2")
    assert page_resp.status_code == 200, page_resp.text
    page = page_resp.json()
    assert len(page) == 2
    assert [item["id"] for item in page] == created_ids[2:4]
