"""Demo API testi — saxta LLM ilə."""
from fastapi.testclient import TestClient

import llm_service
from demo.app import app


def test_demo_endpoints(monkeypatch):
    monkeypatch.setattr(llm_service, "groq_call", lambda m, q: ("Mobil tətbiqdən baxa bilərsiniz.", 10, 5))
    c = TestClient(app)
    assert c.get("/healthz").json() == {"ok": True}
    assert "Bank çatbotu" in c.get("/").text
    r = c.post("/api/ask", json={"message": "Kredit faizi neçədir?"}).json()
    assert r["verdict"] == "ok" and [s["name"] for s in r["trace"]][0] == "gate"
    s = c.get("/api/stats").json()
    assert {"conversations", "resolved_pct", "total_cost_usd", "avg_latency_ms", "pairs"} <= set(s)


def test_demo_validation(monkeypatch):
    monkeypatch.setattr(llm_service, "groq_call", lambda m, q: ("ok", 1, 1))
    c = TestClient(app)
    assert c.post("/api/ask", json={"message": "Salam", "channel": "WhatsApp"}).status_code == 200
    assert c.post("/api/ask", json={"message": ""}).status_code == 422
    assert c.post("/api/ask", json={"message": "x" * 50_000}).status_code == 422
    assert c.post("/api/ask", json={"message": "Salam", "role": "root"}).status_code == 422
