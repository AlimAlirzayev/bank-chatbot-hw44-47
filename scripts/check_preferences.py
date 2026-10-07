"""Dərs #47 — datasetin yoxlanışı (tapşırıqdakı kod + qaydanın kodla təsdiqi)."""
import sys
from pathlib import Path

from datasets import load_dataset

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import violates_secret_rule  # noqa: E402

ds = load_dataset("json", data_files="data/preferences.jsonl", split="train")
print(ds)
print(ds[0])

ok_rule = sum(violates_secret_rule(r["rejected"]) and not violates_secret_rule(r["chosen"]) for r in ds)
ratios = [len(r["chosen"]) / len(r["rejected"]) for r in ds]
print(f"\nnum_rows: {ds.num_rows}")
print(f"qayda (rejected sirr istəyir, chosen istəmir): {ok_rule}/{ds.num_rows}")
print(f"uzunluq nisbəti chosen/rejected: min {min(ratios):.2f}, max {max(ratios):.2f}, "
      f"orta {sum(ratios) / len(ratios):.2f}")
