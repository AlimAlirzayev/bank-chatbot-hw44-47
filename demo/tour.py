"""Kodun izahı: docs/tour.json → sətir aralıqları (ast ilə) → demo üçün JSON və GitHub üçün docs/KOD_IZAHI.md.

Sətir nömrələri əl ilə yazılmır: funksiya və dəyişən adı ilə tapılır, kod dəyişəndə izah sürüşmür.
Yenidən yarat:  python -m demo.tour
"""
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOUR_FILE = ROOT / "docs" / "tour.json"
DOC_FILE = ROOT / "docs" / "KOD_IZAHI.md"
SNIPPET_MAX = 40          # README-də bir parça ən çox bu qədər sətir; tam kod linkdədir


def load() -> dict:
    return json.loads(TOUR_FILE.read_text(encoding="utf-8"))


def allowed_paths(tour: dict) -> list:
    """Yalnız docs/tour.json-da adı çəkilən fayllar göstərilir (.env və s. göstərilmir)."""
    return [f["path"] for f in tour["files"]]


def read_lines(path: str) -> list:
    return (ROOT / path).read_text(encoding="utf-8").splitlines()


def _resolve(path: str, anchor: dict) -> tuple:
    lines = read_lines(path)
    if anchor.get("file"):
        return 1, len(lines)
    if "marker" in anchor:
        start = next(i for i, ln in enumerate(lines, 1) if anchor["marker"] in ln)
        end = next((i - 1 for i, ln in enumerate(lines, 1) if i > start and anchor["until"] in ln), len(lines))
        while end > start and not lines[end - 1].strip():
            end -= 1
        return start, end
    tree = ast.parse("\n".join(lines))
    for node in ast.walk(tree):
        if "func" in anchor and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == anchor["func"]:
            first = min([d.lineno for d in node.decorator_list] + [node.lineno])
            return first, node.end_lineno
        if "assign" in anchor and isinstance(node, ast.Assign) \
                and any(isinstance(t, ast.Name) and t.id == anchor["assign"] for t in node.targets):
            return node.lineno, node.end_lineno
    raise KeyError(f"{path}: anchor tapılmadı {anchor}")


def resolved_stops(tour: dict) -> list:
    out = []
    for s in tour["stops"]:
        ranges = [_resolve(s["file"], s["anchor"])]
        if "also" in s:
            ranges.append(_resolve(s["file"], s["also"]))
        out.append({**{k: v for k, v in s.items() if k not in ("anchor", "also")},
                    "ranges": ranges})            # birinci əsas bölmədir, sonrakı köməkçi parçadır
    return out


def tree(tour: dict) -> list:
    """PyCharm kimi ağac: [{"name": "demo", "children": [...]}, {"name": "pipeline.py", "path": ...}]"""
    root: dict = {}
    for f in tour["files"]:
        node = root
        *dirs, name = f["path"].split("/")
        for d in dirs:
            node = node.setdefault(d + "/", {})
        node[name] = f["path"]

    def walk(d):
        items = sorted(d.items(), key=lambda kv: (not kv[0].endswith("/"), kv[0].lower()))
        return [{"name": k.rstrip("/"), "children": walk(v)} if isinstance(v, dict) else {"name": k, "path": v}
                for k, v in items]
    return walk(root)


def payload() -> dict:
    tour = load()
    return {"tree": tree(tour), "files": {f["path"]: f for f in tour["files"]}, "stops": resolved_stops(tour)}


# ---------------------------------------------------------------- GitHub üçün markdown
def _tree_text(nodes, prefix=""):
    rows = []
    for i, n in enumerate(nodes):
        last = i == len(nodes) - 1
        rows.append(prefix + ("└── " if last else "├── ") + n["name"] + ("/" if "children" in n else ""))
        if "children" in n:
            rows += _tree_text(n["children"], prefix + ("    " if last else "│   "))
    return rows


def markdown() -> str:
    tour = load()
    stops = resolved_stops(tour)
    md = ["# Kodun izahı", "",
          "> Bu fayl `docs/tour.json`-dan avtomatik yaranır (`python -m demo.tour`). Eyni məzmun "
          "demo səhifəsinin **Kodun izahı** tabında da var.", "",
          "```", "bank-chatbot-hw44-47/", *_tree_text(tree(tour)), "```", ""]
    for f in tour["files"]:
        fstops = [s for s in stops if s["file"] == f["path"]]
        md += [f"## `{f['path']}` · {f['lesson']}", "", f["summary"], ""]
        lang = "yaml" if f["path"].endswith(".yml") else "python"
        lines = read_lines(f["path"])
        for s in fstops:
            a, b = s["ranges"][0]
            md += [f"### {s['title']}", "",
                   f"**Dərs:** {s['lesson']} · [`{f['path']}` sətir {a}–{b}](../{f['path']}#L{a}-L{b})", ""]
            for (ra, rb) in s["ranges"]:
                chunk = lines[ra - 1:rb]
                cut = len(chunk) > SNIPPET_MAX
                md += [f"```{lang}", *chunk[:SNIPPET_MAX], *(["# … (tam kod yuxarıdakı linkdədir)"] if cut else []), "```", ""]
            md += [f"- **Nə edir:** {s['what']}", f"- **Niyə belə:** {s['why']}",
                   f"- **Qısa izah:** {s['short']}", ""]
        if not fstops:
            md += [f"[Fayla bax](../{f['path']})", ""]
    return "\n".join(md) + "\n"


if __name__ == "__main__":
    DOC_FILE.write_text(markdown(), encoding="utf-8")
    print(f"{DOC_FILE.relative_to(ROOT)} yazıldı, {len(load()['stops'])} bölmə")
