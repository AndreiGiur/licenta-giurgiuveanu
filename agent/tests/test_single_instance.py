"""Teste pentru garda de instanta unica (agent/single_instance.py).

Functioneaza pe ambele strategii:
  - Windows + pywin32 → named mutex (detectie prin ERROR_ALREADY_EXISTS)
  - POSIX / fallback   → lock-file cu fcntl/msvcrt

Fiecare test foloseste un nume unic ca sa nu se contamineze intre rulari.
"""
import uuid

from agent.single_instance import SingleInstance


def _unique_name() -> str:
    return f"vwtest-{uuid.uuid4().hex[:12]}"


def test_acquire_first_succeeds():
    name = _unique_name()
    guard = SingleInstance(name)
    try:
        assert guard.acquire() is True
        assert guard.acquired is True
    finally:
        guard.release()


def test_second_instance_same_name_fails():
    name = _unique_name()
    first = SingleInstance(name)
    second = SingleInstance(name)
    try:
        assert first.acquire() is True
        # A doua instanta cu acelasi nume nu poate obtine lock-ul
        assert second.acquire() is False
        assert second.acquired is False
    finally:
        first.release()
        second.release()


def test_release_allows_reacquire():
    name = _unique_name()
    first = SingleInstance(name)
    assert first.acquire() is True
    first.release()
    assert first.acquired is False
    # Dupa release, o noua instanta poate obtine lock-ul
    second = SingleInstance(name)
    try:
        assert second.acquire() is True
    finally:
        second.release()


def test_different_names_dont_conflict():
    a = SingleInstance(_unique_name())
    b = SingleInstance(_unique_name())
    try:
        assert a.acquire() is True
        assert b.acquire() is True  # nume diferite → fara conflict
    finally:
        a.release()
        b.release()


def test_acquire_is_idempotent():
    name = _unique_name()
    guard = SingleInstance(name)
    try:
        assert guard.acquire() is True
        assert guard.acquire() is True  # a doua chemare pe acelasi obiect
        assert guard.acquired is True
    finally:
        guard.release()


def test_context_manager_acquires_and_releases():
    name = _unique_name()
    with SingleInstance(name) as guard:
        assert guard.acquired is True
        # In interiorul context-ului, o alta instanta esueaza
        other = SingleInstance(name)
        assert other.acquire() is False
        other.release()
    # La iesirea din context, lock-ul e eliberat → re-acquire posibil
    after = SingleInstance(name)
    try:
        assert after.acquire() is True
    finally:
        after.release()


def test_release_without_acquire_is_safe():
    """release() pe un guard care nu a achizitionat nimic nu arunca."""
    guard = SingleInstance(_unique_name())
    guard.release()  # no-op, fara exceptie
    assert guard.acquired is False
