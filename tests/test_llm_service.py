"""Dərs #45 testləri — saxta LLM ilə (dependency injection), açar və internet lazım deyil."""
import csv

import httpx
import openai

import llm_service
from llm_service import ask, ask_detailed, calc_cost


def fake_llm(calls):
    def llm_call(model, question):
        calls.append((model, question))
        return f"cavab: {question}", 100, 50
    return llm_call


def rate_limited(model, question):
    req = httpx.Request("POST", "https://x")
    raise openai.RateLimitError("429", response=httpx.Response(429, request=req), body=None)


def test_cache_calls_llm_once():
    calls = []
    assert ask("Kartım itib?", llm_call=fake_llm(calls)) == ask("Kartım itib?", llm_call=fake_llm(calls))
    assert len(calls) == 1


def test_calc_cost():
    # qwen: 0.80 $/1M input, 4.00 $/1M output
    assert calc_cost("qwen/qwen3.8-27b", 1000, 500) == round(1000 * 0.80 / 1e6 + 500 * 4.00 / 1e6, 8)
    assert calc_cost("openai/gpt-oss-120b", 1_000_000, 0) == 0.15
    assert calc_cost("naməlum-model", 10, 10) == 0.0


def test_costs_csv_header_and_row(isolated):
    ask("Salam", llm_call=fake_llm([]))
    rows = list(csv.reader((isolated / "costs.csv").open(encoding="utf-8")))
    assert rows[0] == ["tarix", "model", "input_tokens", "output_tokens", "cost_usd"]
    assert len(rows) == 2 and rows[1][2:4] == ["100", "50"]


def test_retry_three_times_then_fallback(monkeypatch):
    sleeps, calls = [], []
    monkeypatch.setattr(llm_service.time, "sleep", sleeps.append)

    def llm_call(model, question):
        calls.append(model)
        if model == llm_service.primary_model():
            rate_limited(model, question)
        return "ehtiyat cavab", 10, 5

    r = ask_detailed("sual", llm_call=llm_call)
    assert calls == [llm_service.primary_model()] * 3 + [llm_service.fallback_model()]
    assert sleeps == [1.0, 2.0]                      # exponential backoff
    assert r["model"] == llm_service.fallback_model() and r["answer"] == "ehtiyat cavab"


def test_everything_down_gives_polite_message():
    assert ask("sual", llm_call=rate_limited) == llm_service.POLITE_ERROR


def test_non_retryable_error_skips_to_fallback():
    calls = []

    def llm_call(model, question):
        calls.append(model)
        if model == llm_service.primary_model():
            raise ValueError("400 bad request")
        return "ok", 1, 1

    assert ask("sual", llm_call=llm_call) == "ok"
    assert calls == [llm_service.primary_model(), llm_service.fallback_model()]
