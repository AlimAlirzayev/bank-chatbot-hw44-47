import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import llm_service  # noqa: E402


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Hər test öz müvəqqəti fayllarına yazır, cache təmiz başlayır, backoff gözləməsi yoxdur."""
    monkeypatch.setenv("COSTS_CSV", str(tmp_path / "costs.csv"))
    monkeypatch.setenv("BOT_LOG_CSV", str(tmp_path / "bot_log.csv"))
    monkeypatch.setenv("HARVEST_JSONL", str(tmp_path / "harvest.jsonl"))
    monkeypatch.setenv("PROMPT_GUARD", "0")
    monkeypatch.setattr(llm_service.time, "sleep", lambda s: None)
    llm_service._cache.clear()
    return tmp_path
