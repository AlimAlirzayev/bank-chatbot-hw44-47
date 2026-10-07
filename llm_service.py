"""Dərs #45 — Production LLMOps: timeout, retry, fallback, xərc qeydiyyatı, cache.

ask(question) -> str həmişə mətn qaytarır: LLM əlçatmaz olduqda da istifadəçi xəta mesajı alır, exception yox.
"""
import csv
import datetime as dt
import os
import time
from pathlib import Path

import httpx
import openai
from dotenv import load_dotenv

load_dotenv()

# USD / 1M token — Groq rəsmi qiymətləri, console.groq.com/docs/models (2026-10-07 yoxlanılıb)
PRICES = {
    "qwen/qwen3.8-27b": {"input": 0.80, "output": 4.00},
    "openai/gpt-oss-120b": {"input": 0.15, "output": 0.60},
    "openai/gpt-oss-20b": {"input": 0.075, "output": 0.30},
}

MAX_ATTEMPTS = 3          # bir model üçün maksimum cəhd
BACKOFF_BASE = 1.0        # 1 s, 2 s, ... (exponential backoff)
RETRYABLE = (openai.RateLimitError, openai.APITimeoutError)   # yalnız MÜVƏQQƏTİ xətalar

POLITE_ERROR = ("Bağışlayın, hazırda cavab verə bilmirəm. Bir neçə dəqiqədən sonra "
                "yenidən yazın və ya bankın 24/7 qaynar xəttinə zəng edin.")

SYSTEM_PROMPT = (
    "Sən bankın Azərbaycan dilində danışan rəqəmsal köməkçisisən. 2-3 qısa cümlə ilə cavab ver. "
    "Müştəridən HEÇ VAXT PIN, CVV, SMS və ya birdəfəlik kod, parol, kartın tam nömrəsini istəmə — "
    "lazım olsa mobil tətbiqə və ya filiala yönləndir. Bilmədiyin rəqəmi, telefon nömrəsini və "
    "statusu uydurma."
)

_cache: dict = {}         # {sual: cavab} — sadə Python lüğəti


# Seçim ölçməyə əsaslanır (2026-10-07): gpt-oss-120b AZ dilində təmiz yazır, 5x ucuzdur və təhlükəli
# promptu özü rədd etdi. Ehtiyat model BAŞQA ailədəndir — eyni anda çökmə ehtimalı azdır.
def primary_model() -> str:
    return os.getenv("PRIMARY_MODEL", "openai/gpt-oss-120b")


def fallback_model() -> str:
    return os.getenv("FALLBACK_MODEL", "qwen/qwen3.8-27b")


def red_team_model() -> str:
    """Red teaming üçün model: təhlükəsiz olmayan promptu rədd etmir (testdə qwen ~1/3 halda məxfi məlumat istədi)."""
    return os.getenv("RED_TEAM_MODEL", "qwen/qwen3.8-27b")


# ---------------------------------------------------------------- xərc
def calc_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    p = PRICES.get(model)
    if not p:
        return 0.0
    return round((input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000, 8)


def log_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    cost = calc_cost(model, input_tokens, output_tokens)
    path = Path(os.getenv("COSTS_CSV", "data/costs.csv"))
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["tarix", "model", "input_tokens", "output_tokens", "cost_usd"])
        w.writerow([dt.datetime.now().isoformat(timespec="seconds"), model,
                    input_tokens, output_tokens, f"{cost:.8f}"])
    return cost


# ---------------------------------------------------------------- real LLM çağırışı
def _client() -> openai.OpenAI:
    return openai.OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url=os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"),
        timeout=15,        # 15 s-dən çox gözləmirik
        max_retries=0,     # SDK-nın gizli retry-ı söndürülüb — retry-ı biz idarə edirik
    )


def make_llm_call(system_prompt: str = SYSTEM_PROMPT):
    """llm_call(model, question) -> (mətn, input_tokens, output_tokens). Testdə saxtası ötürülür."""
    def llm_call(model: str, question: str):
        extra = {}
        if model.startswith("qwen/"):
            extra["reasoning_effort"] = "none"     # düşünmə tokenləri 200 limiti yeməsin
        elif "gpt-oss" in model:
            extra["reasoning_effort"] = "low"
        r = _client().chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": question}],
            max_tokens=200,
            **extra,
        )
        return (r.choices[0].message.content or "").strip(), r.usage.prompt_tokens, r.usage.completion_tokens
    return llm_call


groq_call = make_llm_call()


def _simulated_rate_limit(model, question):
    """Demodakı 'əsas model xətası' seçimi üçün: real 429 xətasının simulyasiyası."""
    req = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    raise openai.RateLimitError("simulated 429", response=httpx.Response(429, request=req), body=None)


# ---------------------------------------------------------------- retry + fallback
def _try_model(model, question, llm_call, events):
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            text, i, o = llm_call(model, question)
            if text:
                return text, i, o
            events.append(f"{model}: boş cavab")
            return None
        except RETRYABLE as e:
            events.append(f"{model}: cəhd {attempt} — {type(e).__name__}")
            if attempt < MAX_ATTEMPTS:
                time.sleep(BACKOFF_BASE * 2 ** (attempt - 1))
        except Exception as e:                        # 401, 400 ... — təkrar etməyin mənası yoxdur
            events.append(f"{model}: {type(e).__name__} — təkrar edilmir")
            return None
    return None


def ask_detailed(question: str, llm_call=None, use_cache: bool = True, fail_primary: bool = False,
                 models=None) -> dict:
    llm_call = llm_call or groq_call
    key = " ".join(question.lower().split())
    if use_cache and key in _cache:
        return {"answer": _cache[key], "model": "cache", "cached": True, "failed": False,
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "events": ["cache: LLM çağırılmadı"]}

    events = []
    for model in models or (primary_model(), fallback_model()):
        call = _simulated_rate_limit if (fail_primary and model == primary_model()) else llm_call
        result = _try_model(model, question, call, events)
        if result:
            text, i, o = result[0], int(result[1] or 0), int(result[2] or 0)
            try:
                cost = log_cost(model, i, o)
            except OSError as e:                      # xərc faylı yazılmasa da cavab müştəriyə gedir
                cost = calc_cost(model, i, o)
                events.append(f"costs.csv yazılmadı: {type(e).__name__}")
            if use_cache:
                _cache[key] = text
            return {"answer": text, "model": model, "cached": False, "failed": False,
                    "input_tokens": i, "output_tokens": o, "cost_usd": cost, "events": events}
    return {"answer": POLITE_ERROR, "model": None, "cached": False, "failed": True,
            "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "events": events}


def ask(question: str, llm_call=None) -> str:
    return ask_detailed(question, llm_call)["answer"]


if __name__ == "__main__":
    for q in ["Kartım itib, nə etməliyəm?", "Kredit faizi necə hesablanır?",
              "Mobil tətbiqdə köçürmə limiti necə artırılır?", "Hesab çıxarışını haradan ala bilərəm?",
              "Kartım itib, nə etməliyəm?"]:          # sonuncu təkrardır → cache
        print("S:", q)
        print("C:", ask(q), "\n")
