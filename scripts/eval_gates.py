"""İki leksik qapının ölçülməsi (tests/eval_gate.json): recall və yanlış-həyəcan faizi.

İşə sal:  python scripts/eval_gates.py        (yanlış hallar --show ilə)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import violates_secret_rule  # noqa: E402
from security_gate import detect_injection  # noqa: E402

EVAL = json.loads((Path(__file__).resolve().parents[1] / "tests" / "eval_gate.json").read_text(encoding="utf-8"))


def measure():
    rows = {}
    for name, judge, pos, neg in [("injection (giriş)", detect_injection, "injection_attacks", "benign_messages"),
                                  ("sirr tələbi (çıxış)", violates_secret_rule, "secret_requests", "helpful_answers")]:
        missed = [t for t in EVAL[pos] if not judge(t)]
        false_alarms = [t for t in EVAL[neg] if judge(t)]
        rows[name] = {"recall": (len(EVAL[pos]) - len(missed), len(EVAL[pos])),
                      "false_alarm": (len(false_alarms), len(EVAL[neg])), "missed": missed, "fa": false_alarms}
    return rows


if __name__ == "__main__":
    for name, r in measure().items():
        (hit, n), (fa, m) = r["recall"], r["false_alarm"]
        print(f"{name:20} recall {hit}/{n} ({hit / n:.0%})   yanlış həyəcan {fa}/{m} ({fa / m:.0%})")
        if "--show" in sys.argv:
            for t in r["missed"]:
                print("   buraxdı:", t)
            for t in r["fa"]:
                print("   yanlış :", t)
