"""Dərs #46 — dashboard-un rəqəmləri və 3 sualın cavabı üçün faktlar (bot_log.csv-dən)."""
import csv
import sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "data/bot_log.csv"
rows = list(csv.DictReader(open(path, encoding="utf-8")))
n = len(rows)
res = sum(int(r["resolved"]) for r in rows)
cost = sum(float(r["cost_usd"]) for r in rows)
lat = sum(int(r["latency_ms"]) for r in rows) / n
print(f"KPI  söhbət: {n} | həll faizi: {res / n:.1%} | ümumi xərc: ${cost:.5f} | orta gecikmə: {lat / 1000:.2f} san")


def group(key, value):
    g = defaultdict(list)
    for r in rows:
        g[r[key]].append(value(r))
    return g


print("\nMövzu üzrə həll faizi (ən zəifdən):")
for k, v in sorted(group("topic", lambda r: int(r["resolved"])).items(), key=lambda kv: sum(kv[1]) / len(kv[1])):
    print(f"  {k:8} {sum(v) / len(v):6.1%}  ({len(v)} söhbət)")

print("\nModel üzrə xərc:")
for k, v in sorted(group("model", lambda r: float(r["cost_usd"])).items(), key=lambda kv: -sum(kv[1])):
    calls = len(v)
    print(f"  {k or '(model yox)':22} ${sum(v):.5f}  {calls} söhbət  orta ${sum(v) / calls:.6f}")

print("\ngate_verdict (yeni sahə — təhlükəsizlik qatı):")
for k, v in sorted(group("gate_verdict", lambda r: 1).items(), key=lambda kv: -len(kv[1])):
    print(f"  {k:15} {len(v)}")

print("\nKanal × gate_verdict:")
for ch, v in group("channel", lambda r: r["gate_verdict"]).items():
    print(f"  {ch:10} " + ", ".join(f"{x}={v.count(x)}" for x in sorted(set(v))))
