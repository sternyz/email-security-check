"""Tests for app/rate_limit.py and its wiring into /api/check.

No network: the limiter is driven by a fake clock, and the endpoint tests
patch out run_all_checks since only the HTTP guard behavior is under test.
"""

import threading

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.rate_limit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_allows_up_to_the_limit_then_blocks_with_retry_after():
    clock = FakeClock()
    limiter = RateLimiter([(3, 60)], clock=clock)

    assert [limiter.hit("1.2.3.4") for _ in range(3)] == [None, None, None]
    clock.now += 10
    assert limiter.hit("1.2.3.4") == pytest.approx(50)


def test_window_slides_so_old_hits_age_out():
    clock = FakeClock()
    limiter = RateLimiter([(2, 60)], clock=clock)
    limiter.hit("1.2.3.4")
    clock.now += 30
    limiter.hit("1.2.3.4")

    clock.now += 31  # first hit is now outside the window
    assert limiter.hit("1.2.3.4") is None
    assert limiter.hit("1.2.3.4") is not None


def test_rejected_requests_do_not_extend_the_block():
    clock = FakeClock()
    limiter = RateLimiter([(1, 60)], clock=clock)
    limiter.hit("1.2.3.4")
    for _ in range(5):
        clock.now += 10
        limiter.hit("1.2.3.4")

    clock.now += 11  # 61s after the only recorded hit
    assert limiter.hit("1.2.3.4") is None


def test_limits_are_per_client():
    limiter = RateLimiter([(1, 60)], clock=FakeClock())
    assert limiter.hit("1.1.1.1") is None
    assert limiter.hit("1.1.1.1") is not None
    assert limiter.hit("2.2.2.2") is None


def test_longer_window_applies_after_short_one_resets():
    clock = FakeClock()
    limiter = RateLimiter([(2, 60), (3, 3600)], clock=clock)
    limiter.hit("ip")
    limiter.hit("ip")
    clock.now += 61
    assert limiter.hit("ip") is None  # third hit, per-minute window reset

    clock.now += 61
    retry = limiter.hit("ip")  # hourly limit of 3 reached
    assert retry == pytest.approx(3600 - 122)


def test_sweep_drops_idle_clients():
    clock = FakeClock()
    limiter = RateLimiter([(1, 60)], clock=clock)
    limiter.hit("idle")
    clock.now += 400
    limiter.hit("active")
    assert set(limiter._hits) == {"active"}


# --- endpoint wiring ---

FAKE_RESULTS = [{"key": "dmarc", "status": "pass"}]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "limiter", RateLimiter([(2, 60)]))
    monkeypatch.setattr(main, "check_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(main, "run_all_checks", lambda domain: FAKE_RESULTS)
    monkeypatch.setattr(main, "compute_verdict", lambda results: {"level": "good"})
    return TestClient(main.app)


def test_endpoint_returns_429_with_retry_after_once_limit_hit(client):
    for _ in range(2):
        assert client.post("/api/check", json={"email": "a@example.com"}).status_code == 200

    response = client.post("/api/check", json={"email": "a@example.com"})
    assert response.status_code == 429
    assert response.json()["detail"] == main.RATE_LIMITED_MESSAGE
    assert 0 < int(response.headers["Retry-After"]) <= 60


def test_endpoint_returns_503_when_all_slots_busy(client):
    assert main.check_slots.acquire(blocking=False)  # simulate a check in flight
    try:
        response = client.post("/api/check", json={"email": "a@example.com"})
    finally:
        main.check_slots.release()

    assert response.status_code == 503
    assert response.json()["detail"] == main.BUSY_MESSAGE
    # A busy rejection shouldn't have used up quota: both allowed hits remain.
    for _ in range(2):
        assert client.post("/api/check", json={"email": "a@example.com"}).status_code == 200


def test_slot_is_released_when_a_check_raises(client, monkeypatch):
    def boom(domain):
        raise RuntimeError("dns exploded")

    monkeypatch.setattr(main, "run_all_checks", boom)
    with pytest.raises(RuntimeError):
        client.post("/api/check", json={"email": "a@example.com"})

    assert main.check_slots.acquire(blocking=False)
    main.check_slots.release()


def test_malformed_email_does_not_count_against_quota(client):
    for _ in range(3):
        assert client.post("/api/check", json={"email": "nope"}).status_code == 422
    assert client.post("/api/check", json={"email": "a@example.com"}).status_code == 200
