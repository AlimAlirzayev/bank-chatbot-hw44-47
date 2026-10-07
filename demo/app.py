"""Demo tətbiqi: mesajın 5 emal mərhələsini, KPI-ları və DPO datasını göstərir, kodun izahını verir.

İşə sal:  uvicorn demo.app:app --port 8931
"""
import csv
import json
import os
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from typing import Literal

from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pipeline  # noqa: E402
from demo import tour  # noqa: E402

BASE_LOG = ROOT / "data" / "bot_log.csv"            # 60 söhbətlik əsas data (Power BI-a gedən)
BASE_PAIRS = ROOT / "data" / "preferences.jsonl"    # 15 cütlük əsas dataset

app = FastAPI(title="Bank çatbotu")


class AskIn(BaseModel):
    # Rol seçicisi DƏRS ÜÇÜN nəzarət düyməsidir (icazə matrisini göstərmək üçün).
    # Real sistemdə rol sessiyadan/autentifikasiyadan gəlir, sorğunun gövdəsindən yox.
    message: str = Field(min_length=1, max_length=pipeline.MAX_MESSAGE_CHARS)
    role: Literal["customer_bot", "support_bot", "admin_bot"] = "customer_bot"
    channel: str = Field("web", max_length=20)     # "Web" və "web" ikisi də qəbul; naməlum → Web
    fail_primary: bool = False
    red_team: bool = False
    confirm: bool = False


def _rows(path: Path):
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _lines(path: Path):
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _live_log() -> Path:
    return Path(os.getenv("BOT_LOG_CSV", "data/bot_log.csv"))


def _live_pairs() -> Path:
    return Path(os.getenv("HARVEST_JSONL", "data/harvest_live.jsonl"))


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(ROOT / "demo" / "index.html")


@app.post("/api/ask")
def api_ask(body: AskIn):
    return pipeline.handle(body.message, role=body.role, channel=body.channel,
                           fail_primary=body.fail_primary, red_team=body.red_team, confirm=body.confirm)


@app.get("/api/stats")
def api_stats():
    live = _live_log()
    rows = _rows(BASE_LOG) + ([] if live.resolve() == BASE_LOG.resolve() else _rows(live))
    pairs_live = _lines(_live_pairs())
    n = len(rows)
    verdicts = {}
    for r in rows:
        verdicts[r["gate_verdict"]] = verdicts.get(r["gate_verdict"], 0) + 1
    return {
        "conversations": n,
        "resolved_pct": round(100 * sum(int(r["resolved"]) for r in rows) / n, 1) if n else 0.0,
        "total_cost_usd": round(sum(float(r["cost_usd"]) for r in rows), 6),
        "avg_latency_ms": round(sum(int(r["latency_ms"]) for r in rows) / n) if n else 0,
        "pairs": len(_lines(BASE_PAIRS)) + len(pairs_live),
        "pairs_live": len(pairs_live),
        "verdicts": verdicts,
        "last_pair": (pairs_live or _lines(BASE_PAIRS) or [None])[-1],
    }


@app.get("/api/tour")
def api_tour():
    return tour.payload()


@app.get("/api/code")
def api_code(path: str):
    # yalnız turda adı çəkilən fayllar — ağ siyahı; ".env", "../" və s. 404
    if path not in tour.allowed_paths(tour.load()):
        raise HTTPException(status_code=404, detail="fayl turda yoxdur")
    return {"path": path, "lines": tour.read_lines(path)}
