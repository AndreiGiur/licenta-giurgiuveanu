"""Unit tests pentru MetricsTracker — logica de cache local pentru scanari."""
import json
from pathlib import Path

import pytest

from agent import core


def test_metrics_tracker_returns_empty_state_when_file_missing(tmp_path):
    """Daca metrics.json nu exista, state-ul e gol cu valori default."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)

    assert tracker.state["scans_total"] == 0
    assert tracker.state["last_exposure_score"] is None
    assert tracker.state["last_scan_at"] is None
    assert tracker.state["history"] == []
    assert tracker.state["version"] == 1


def test_metrics_tracker_records_scan_and_persists_atomically(tmp_path):
    """record_scan incrementeaza counters, adauga history entry, salveaza pe disk."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)

    tracker.record_scan(score=42, scan_type="standard", job_id=128)
    tracker.record_scan(score=37, scan_type="deep", job_id=129)

    assert tracker.state["scans_total"] == 2
    assert tracker.state["last_exposure_score"] == 37
    assert tracker.state["last_scan_at"] is not None
    assert len(tracker.state["history"]) == 2
    # Cele mai recente prime
    assert tracker.state["history"][0]["job_id"] == 129
    assert tracker.state["history"][1]["job_id"] == 128

    # Persistat pe disk + reluabil dintr-o instanta noua
    assert cache.exists()
    tracker2 = core.MetricsTracker(cache)
    assert tracker2.state["scans_total"] == 2
    assert tracker2.state["last_exposure_score"] == 37


def test_metrics_tracker_history_capped_at_20(tmp_path):
    """History tine doar ultimele 20 entries."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)

    for i in range(25):
        tracker.record_scan(score=i, scan_type="standard", job_id=i)

    assert tracker.state["scans_total"] == 25
    assert len(tracker.state["history"]) == 20
    # Cele mai recente prime — primul e job_id=24, ultimul e job_id=5
    assert tracker.state["history"][0]["job_id"] == 24
    assert tracker.state["history"][19]["job_id"] == 5


def test_metrics_tracker_corrupt_json_falls_back_to_empty(tmp_path):
    """JSON invalid → state gol, fara crash."""
    cache = tmp_path / "metrics.json"
    cache.write_text("{not valid json", encoding="utf-8")

    tracker = core.MetricsTracker(cache)
    assert tracker.state["scans_total"] == 0
    assert tracker.state["history"] == []


def test_metrics_tracker_reset_clears_disk(tmp_path):
    """reset() goleste state-ul si sterge fisierul."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)
    tracker.record_scan(score=50, scan_type="standard", job_id=1)
    assert cache.exists()

    tracker.reset()
    assert tracker.state["scans_total"] == 0
    assert not cache.exists()
