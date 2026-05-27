"""Teste pentru rate limiting pe endpoint-urile sensibile (login, register).

Aceste teste activeaza explicit rate limiter-ul (override-uind DISABLE_RATELIMIT
din conftest) pentru a verifica ca:
  - Limita 5/minut este aplicata
  - HTTP 429 este returnat cand limita e depasita
  - Limiter-ul filtreaza pe IP
"""
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def ratelimit_client(client):
    """TestClient cu rate limiting ACTIVAT temporar.

    Reuseste app-ul + limiter-ul deja initializat (singura instanta) si
    activeaza/dezactiveaza via atribut `enabled`. Reset-ul la cleanup asigura
    ca testele urmatoare nu primesc 429.
    """
    from server.app.ratelimit import limiter
    limiter.enabled = True
    # Reset storage intern al limiter-ului ca sa nu mosteneasca counters
    # din testele anterioare (TestClient toate vin din acelasi IP "testclient")
    limiter.reset()
    yield client
    limiter.enabled = False
    limiter.reset()


def test_login_rate_limit_returns_429_after_5_requests(ratelimit_client):
    """A 6-a incercare consecutiva de login intr-un minut → HTTP 429."""
    payload = {"email": "nobody@example.com", "password": "wrongpass"}
    statuses = []
    for _ in range(6):
        r = ratelimit_client.post("/api/v1/auth/login", json=payload)
        statuses.append(r.status_code)
    # Primele 5 trec (returneaza 401 fiindca credentials invalide)
    assert statuses[:5].count(401) == 5, f"primele 5 ar trebui 401: {statuses}"
    # Al 6-lea trebuie sa fie 429
    assert statuses[5] == 429, f"al 6-lea ar trebui 429, got {statuses[5]}"


def test_register_rate_limit_returns_429_after_5_requests(ratelimit_client):
    """A 6-a incercare consecutiva de register intr-un minut → HTTP 429."""
    statuses = []
    for i in range(6):
        # Email diferit la fiecare incercare ca sa nu trigger 'already registered'
        r = ratelimit_client.post(
            "/api/v1/auth/register",
            json={"email": f"rl-test-{i}@example.com", "password": "abcd1234"},
        )
        statuses.append(r.status_code)
    # 5 reusite (200) + 1 limitat (429)
    successes = sum(1 for s in statuses if s == 200)
    limited = sum(1 for s in statuses if s == 429)
    assert successes == 5 and limited == 1, (
        f"asteptat 5x200 + 1x429, primit: {statuses}"
    )
