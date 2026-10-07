"""Kodun izahı: hər bölmə real koda bağlıdır, GitHub sənədi aktualdır, kod endpoint-i yalnız ağ siyahını qaytarır."""
from fastapi.testclient import TestClient

from demo import tour
from demo.app import app


def test_every_stop_resolves_to_real_lines():
    p = tour.payload()
    assert len(p["stops"]) >= 15
    for s in p["stops"]:
        lines = tour.read_lines(s["file"])
        for a, b in s["ranges"]:
            assert 1 <= a <= b <= len(lines), s["id"]
        assert all(s[k] for k in ("title", "what", "why", "short", "lesson"))


def test_github_doc_is_up_to_date():
    # docs/KOD_IZAHI.md əl ilə yazılmır, `python -m demo.tour` ilə yaranır
    assert tour.DOC_FILE.read_text(encoding="utf-8") == tour.markdown()


def test_code_endpoint_whitelist_only():
    c = TestClient(app)
    assert c.get("/api/code", params={"path": "pipeline.py"}).status_code == 200
    for bad in (".env", "../.env", "/etc/passwd", "data/bot_log.csv", ".env.example"):
        assert c.get("/api/code", params={"path": bad}).status_code == 404, bad
    assert c.get("/api/tour").json()["tree"]
