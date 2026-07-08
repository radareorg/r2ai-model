#!/usr/bin/env python3
"""Generate and verify radare2 training datasets with local evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_R2_SOURCE = Path(os.environ.get("R2_SOURCE", str(ROOT.parent / "radare2")))
DEFAULT_R2_BIN_CANDIDATES = [
    os.environ.get("R2_BIN"),
    str(DEFAULT_R2_SOURCE / "b" / "binr" / "radare2" / "radare2"),
    str(DEFAULT_R2_SOURCE / "binr" / "radare2" / "radare2"),
    shutil.which("r2"),
    shutil.which("radare2"),
]
KNOWLEDGE_PATH = ROOT / "data" / "agentic-knowledge" / "knowledge.jsonl"

DATASETS = {
    "r2cmd": {
        "seed": ROOT / "data" / "radare2-agentic" / "seeds.json",
        "verified": ROOT / "data" / "radare2-agentic" / "verified.jsonl",
        "pending": ROOT / "data" / "radare2-agentic" / "pending-human.jsonl",
    },
    "r2js": {
        "seed": ROOT / "data" / "r2js" / "seeds.json",
        "verified": ROOT / "data" / "r2js" / "verified.jsonl",
        "pending": ROOT / "data" / "r2js" / "pending-human.jsonl",
    },
    "reasoning": {
        "seed": ROOT / "data" / "reasoning-long" / "tasks.json",
        "verified": ROOT / "data" / "reasoning-long" / "verified.jsonl",
        "pending": ROOT / "data" / "reasoning-long" / "pending-human.jsonl",
    },
}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]")


@dataclass
class Verification:
    ok: bool
    status: str
    output: str
    command_line: list[str]
    checks: list[dict[str, Any]]
    elapsed_ms: int
    returncode: int
    reason: str = ""


def pick_r2_bin(explicit: str | None = None) -> Path:
    candidates = [explicit] if explicit else DEFAULT_R2_BIN_CANDIDATES
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists() and path.is_file():
            return path
        found = shutil.which(str(candidate))
        if found:
            return Path(found)
    raise SystemExit("Cannot find radare2. Set R2_BIN=/path/to/radare2.")


def load_json(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")
    return data


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def fixture_path(entry: dict[str, Any], r2_source: Path) -> str:
    fixture = entry.get("fixture", "-")
    if fixture in ("-", "--"):
        return fixture
    path = Path(fixture)
    if path.is_absolute():
        return str(path)
    return str(r2_source / fixture)


def relative_to_r2_source(path: str, r2_source: Path) -> str:
    if path in ("-", "--"):
        return path
    p = Path(path)
    try:
        return p.resolve().relative_to(r2_source.resolve()).as_posix()
    except (OSError, ValueError):
        return path


def fixture_ref(entry: dict[str, Any], r2_source: Path) -> str:
    return relative_to_r2_source(fixture_path(entry, r2_source), r2_source)


def expand_r2_refs(text: str, r2_source: Path) -> str:
    return text.replace("${R2_SOURCE}", str(r2_source)).replace("{R2_SOURCE}", str(r2_source))


def sanitize_text(text: str, r2_source: Path) -> str:
    sanitized = text.replace(str(r2_source) + os.sep, "")
    sanitized = sanitized.replace(str(r2_source), ".")
    sanitized = re.sub(r"/tmp/tmp[^\s'\"]+\.r2\.js", "<generated-r2js-script>", sanitized)
    sanitized = re.sub(r"/home/[^/\s]+/", "$HOME/", sanitized)
    return sanitized


def sanitize_command_line(args: list[str], r2_source: Path, r2_bin: Path) -> list[str]:
    sanitized = []
    for idx, arg in enumerate(args):
        if idx == 0 and Path(arg) == r2_bin:
            sanitized.append("radare2")
        elif re.match(r"/tmp/tmp[^\s]+\.r2\.js$", arg):
            sanitized.append("<generated-r2js-script>")
        else:
            sanitized.append(sanitize_text(arg, r2_source))
    return sanitized


def clean_output(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r\n", "\n")


def simple_json_path(value: Any, path: str) -> Any:
    cur = value
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur[part]
        elif isinstance(cur, list):
            cur = cur[int(part)]
        else:
            raise KeyError(path)
    return cur


def evaluate_checks(output: str, checks: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]], str]:
    results: list[dict[str, Any]] = []
    for check in checks:
        ctype = check.get("type", "contains")
        passed = False
        detail = ""
        try:
            if ctype == "contains":
                passed = str(check["value"]) in output
            elif ctype == "not_contains":
                passed = str(check["value"]) not in output
            elif ctype == "regex":
                passed = re.search(str(check["value"]), output, re.MULTILINE) is not None
            elif ctype == "nonempty":
                passed = bool(output.strip())
            elif ctype == "line_count_gte":
                passed = len([line for line in output.splitlines() if line.strip()]) >= int(check["value"])
            elif ctype == "json_path_equals":
                parsed = json.loads(output)
                found = simple_json_path(parsed, str(check["path"]))
                passed = found == check["value"]
                detail = repr(found)
            else:
                detail = f"unknown check type {ctype}"
        except Exception as exc:
            detail = str(exc)
        item = dict(check)
        item["passed"] = passed
        if detail:
            item["detail"] = detail
        results.append(item)
        if not passed:
            return False, results, f"failed check: {check}"
    return True, results, ""


def build_r2_args(entry: dict[str, Any], r2_bin: Path, r2_source: Path, script_file: str | None = None) -> list[str]:
    args = [str(r2_bin), "-2", "-NN", "-q", "-e", "scr.color=0"]
    if entry.get("analyze_on_open"):
        args.append("-A")
    if script_file:
        args.extend(["-i", script_file])
    for setup in entry.get("setup", []):
        args.extend(["-c", expand_r2_refs(setup, r2_source)])
    kind = entry.get("kind")
    if kind == "r2cmd":
        args.extend(["-c", expand_r2_refs(entry["answer"], r2_source)])
    elif kind == "r2js" and not script_file:
        script = entry.get("script", entry.get("answer", ""))
        args.extend(["-c", expand_r2_refs(script if script.startswith("js ") else "js " + script, r2_source)])
    elif kind == "reasoning_task":
        for cmd in entry.get("starter_commands", []):
            args.extend(["-c", expand_r2_refs(cmd, r2_source)])
    args.extend(["-c", "q", fixture_path(entry, r2_source)])
    return args


def run_entry(entry: dict[str, Any], r2_bin: Path, r2_source: Path, timeout: int) -> Verification:
    script_text = entry.get("script") if entry.get("kind") == "r2js" else None
    start = time.monotonic()
    tmp_name = None
    try:
        if script_text and not str(script_text).lstrip().startswith("js "):
            with tempfile.NamedTemporaryFile("w", suffix=".r2.js", delete=False, encoding="utf-8") as tmp:
                tmp.write(script_text)
                tmp_name = tmp.name
            args = build_r2_args(entry, r2_bin, r2_source, tmp_name)
        else:
            args = build_r2_args(entry, r2_bin, r2_source)
        proc = subprocess.run(
            args,
            cwd=str(r2_source if r2_source.is_dir() else ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed = int((time.monotonic() - start) * 1000)
        output = clean_output(proc.stdout + proc.stderr)
        if proc.returncode != 0:
            return Verification(False, "r2-error", output, args, [], elapsed, proc.returncode, "radare2 returned non-zero")
        ok, checks, reason = evaluate_checks(output, entry.get("checks", [{"type": "nonempty"}]))
        return Verification(ok, "ok" if ok else "check-failed", output, args, checks, elapsed, proc.returncode, reason)
    except subprocess.TimeoutExpired as exc:
        output = clean_output((exc.stdout or "") + (exc.stderr or ""))
        elapsed = int((time.monotonic() - start) * 1000)
        return Verification(False, "timeout", output, [], [], elapsed, 124, f"timed out after {timeout}s")
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def repair_candidates(entry: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for hint in entry.get("repair_hints", []):
        repaired = copy.deepcopy(entry)
        if "prepend_setup" in hint:
            repaired["setup"] = list(hint["prepend_setup"]) + repaired.get("setup", [])
        if "append_setup" in hint:
            repaired["setup"] = repaired.get("setup", []) + list(hint["append_setup"])
        if "answer" in hint:
            repaired["answer"] = hint["answer"]
        if "fixture" in hint:
            repaired["fixture"] = hint["fixture"]
        repaired["id"] = repaired.get("id", "candidate") + ".repair"
        candidates.append(repaired)
    return candidates


def verify_with_repair(entry: dict[str, Any], r2_bin: Path, r2_source: Path, timeout: int) -> tuple[dict[str, Any], Verification]:
    verification = run_entry(entry, r2_bin, r2_source, timeout)
    if verification.ok:
        return entry, verification
    for candidate in repair_candidates(entry):
        repaired_verification = run_entry(candidate, r2_bin, r2_source, timeout)
        if repaired_verification.ok:
            candidate["repaired_from"] = entry.get("id")
            return candidate, repaired_verification
    return entry, verification


def output_excerpt(output: str, limit: int = 1200) -> str:
    out = output.strip()
    if len(out) <= limit:
        return out
    return out[:limit] + "\n[truncated]"


def row_from_entry(entry: dict[str, Any], verification: Verification, r2_source: Path, r2_bin: Path) -> dict[str, Any]:
    kind = entry["kind"]
    if kind == "reasoning_task":
        system = "You are a radare2 reverse engineering assistant. Reason carefully and ground claims in command evidence."
        assistant = entry["answer"]
    elif kind == "r2js":
        system = "***RADARE2 R2JS MODE: ON***"
        assistant = entry.get("answer") or entry.get("script", "")
    else:
        system = "***RADARE2 MODE: ON***"
        assistant = entry["answer"]
    return {
        "id": entry["id"],
        "kind": kind,
        "tags": entry.get("tags", []),
        "fixture": fixture_ref(entry, r2_source),
        "source_refs": entry.get("source_refs", []),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": entry["question"]},
            {"role": "assistant", "content": assistant},
        ],
        "verification": {
            "status": verification.status,
            "returncode": verification.returncode,
            "elapsed_ms": verification.elapsed_ms,
            "command_line": sanitize_command_line(verification.command_line, r2_source, r2_bin),
            "checks": verification.checks,
            "output_sha256": hashlib.sha256(sanitize_text(verification.output, r2_source).encode("utf-8")).hexdigest(),
            "output_excerpt": output_excerpt(sanitize_text(verification.output, r2_source)),
        },
    }


def pending_from_entry(dataset: str, entry: dict[str, Any], verification: Verification, r2_source: Path) -> dict[str, Any]:
    return {
        "dataset": dataset,
        "id": entry.get("id", ""),
        "kind": entry.get("kind", ""),
        "question": entry.get("question", ""),
        "proposed_answer": entry.get("answer", entry.get("script", "")),
        "fixture": fixture_ref(entry, r2_source),
        "reason": verification.reason or verification.status,
        "status": verification.status,
        "output_excerpt": output_excerpt(sanitize_text(verification.output, r2_source), 600),
        "source_refs": entry.get("source_refs", []),
    }


def write_human_tsv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = ["dataset", "id", "kind", "question", "proposed_answer", "fixture", "reason", "status", "source_refs"]
    with path.open("w", encoding="utf-8") as f:
        f.write("\t".join(columns) + "\n")
        for row in rows:
            values = []
            for col in columns:
                value = row.get(col, "")
                if isinstance(value, list):
                    value = ",".join(map(str, value))
                values.append(str(value).replace("\t", " ").replace("\n", "\\n"))
            f.write("\t".join(values) + "\n")


HELP_TOPICS = [
    ("cmd.syntax.js", "j?", "JavaScript command dispatcher help", ["libr/core/cmd.c"]),
    ("cmd.info", "i?", "Binary information command help", ["libr/core/cmd_info.inc.c"]),
    ("cmd.analysis.functions", "afl?", "Function listing command help", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.xrefs", "axt?", "Cross-reference command help", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.filesystems", "m?", "Mount and filesystem command help", ["libr/fs", "libr/core"]),
]


def knowledge_messages(question: str, answer: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": "You are a radare2 knowledge-base builder. Prefer precise, source-grounded facts."},
        {"role": "user", "content": question},
        {"role": "assistant", "content": answer},
    ]


def build_help_knowledge(r2_bin: Path, r2_source: Path, timeout: int) -> list[dict[str, Any]]:
    rows = []
    for topic, command, title, refs in HELP_TOPICS:
        entry = {
            "id": f"knowledge.{topic}",
            "kind": "r2cmd",
            "answer": command,
            "fixture": "--",
            "checks": [{"type": "nonempty"}],
        }
        verification = run_entry(entry, r2_bin, r2_source, timeout)
        if not verification.ok:
            continue
        answer = output_excerpt(sanitize_text(verification.output, r2_source), 1800)
        rows.append({
            "id": f"knowledge.{topic}",
            "kind": "agentic_knowledge",
            "topic": topic,
            "source_refs": refs,
            "messages": knowledge_messages(f"What does radare2 document for `{command}`?", answer),
            "verification": {
                "status": verification.status,
                "command_line": sanitize_command_line(verification.command_line, r2_source, r2_bin),
                "output_sha256": hashlib.sha256(answer.encode("utf-8")).hexdigest(),
            },
            "title": title,
        })
    return rows


def summarize_r2js_script(path: Path) -> tuple[str, list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    apis = sorted(set(re.findall(r"r2\.(cmdj|cmd0|cmdAt|cmd|callAt|call|syscmds|plugin|unload|log)", text)))
    comments = []
    for line in text.splitlines()[:20]:
        stripped = line.strip().lstrip("/* ").rstrip(" */")
        if stripped and (line.strip().startswith("//") or line.strip().startswith("/*") or line.strip().startswith("*")):
            comments.append(stripped)
    summary = " ".join(comments[:3]) or f"r2js script using APIs: {', '.join(apis)}"
    summary = re.sub(r"\b[pP]ancake\b", "radare2 contributor", summary)
    summary = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "<email>", summary)
    return summary, apis


def build_r2js_script_knowledge(r2_source: Path) -> list[dict[str, Any]]:
    scripts_dir = r2_source / "scripts"
    if not scripts_dir.is_dir():
        return []
    rows = []
    for path in sorted(scripts_dir.glob("*.r2.js")):
        summary, apis = summarize_r2js_script(path)
        if not apis:
            continue
        ref = relative_to_r2_source(str(path), r2_source)
        answer = f"`{ref}` is an r2js script. Summary: {summary}. Observed r2 APIs: {', '.join('r2.' + api for api in apis)}."
        rows.append({
            "id": "knowledge.r2js.script." + path.stem.replace(".", "_"),
            "kind": "agentic_knowledge",
            "topic": "r2js.script",
            "source_refs": [ref],
            "messages": knowledge_messages(f"What radare2 JavaScript APIs does `{ref}` demonstrate?", answer),
            "tags": ["r2js", "script", *apis],
        })
    return rows


def write_knowledge_base(r2_bin: Path, r2_source: Path, timeout: int) -> int:
    rows = build_help_knowledge(r2_bin, r2_source, timeout)
    rows.extend(build_r2js_script_knowledge(r2_source))
    write_jsonl(KNOWLEDGE_PATH, rows)
    return len(rows)


def selected_datasets(name: str) -> list[str]:
    if name == "all":
        return list(DATASETS)
    if name not in DATASETS:
        raise SystemExit(f"unknown dataset {name}")
    return [name]


def build(args: argparse.Namespace) -> int:
    r2_bin = pick_r2_bin(args.r2_bin)
    r2_source = Path(args.r2_source)
    all_pending: list[dict[str, Any]] = []
    for dataset in selected_datasets(args.dataset):
        paths = DATASETS[dataset]
        seeds = load_json(paths["seed"])
        verified_rows: list[dict[str, Any]] = []
        pending_rows: list[dict[str, Any]] = []
        for entry in seeds:
            checked_entry, verification = verify_with_repair(entry, r2_bin, r2_source, args.timeout)
            if verification.ok:
                verified_rows.append(row_from_entry(checked_entry, verification, r2_source, r2_bin))
                print(f"ok {dataset} {checked_entry['id']}")
            else:
                pending = pending_from_entry(dataset, checked_entry, verification, r2_source)
                pending_rows.append(pending)
                all_pending.append(pending)
                print(f"pending {dataset} {checked_entry.get('id', '')}: {verification.reason or verification.status}")
        if not args.dry_run:
            write_jsonl(paths["verified"], verified_rows)
            write_jsonl(paths["pending"], pending_rows)
    if not args.dry_run and args.dataset == "all":
        knowledge_count = write_knowledge_base(r2_bin, r2_source, args.timeout)
        print(f"knowledge agentic {knowledge_count} rows")
    if not args.dry_run:
        write_human_tsv(ROOT / "data" / "agentic-review" / "generated-failures.tsv", all_pending)
    return 0 if not all_pending else 1


def source_snippet(path: Path, start: int, lines: int = 40) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    begin = max(start - 1, 0)
    end = min(begin + lines, len(text))
    return "\n".join(f"{idx + 1}: {text[idx]}" for idx in range(begin, end))


def propose(args: argparse.Namespace) -> int:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is required for propose")
    try:
        import openai  # type: ignore
    except ImportError as exc:
        raise SystemExit("The openai package is required for propose") from exc

    r2_source = Path(args.r2_source)
    context = "\n\n".join(
        [
            source_snippet(r2_source / "libr/core/cmd.c", 174, 16),
            source_snippet(r2_source / "libr/core/cmd.c", 1430, 125),
            source_snippet(r2_source / "scripts/whatarch.r2.js", 1, 80),
            source_snippet(r2_source / "scripts/tags.r2.js", 1, 100),
        ]
    )
    prompt = f"""Generate {args.count} radare2 dataset candidates as JSON.
Each item must have id, kind, question, answer or script, fixture, checks, tags.
Use only commands that can be verified by radare2 on fixtures under test/bins.
Prefer action-to-r2command examples and r2js examples.

Source context:
{context}
"""
    client = openai.OpenAI(base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    response = client.chat.completions.create(
        model=args.model,
        messages=[{"role": "user", "content": prompt}],
        temperature=args.temperature,
        top_p=0.9,
        max_tokens=8000,
    )
    text = (response.choices[0].message.content or "[]").replace("```json", "").replace("```", "").strip()
    try:
        proposals = json.loads(text)
    except json.JSONDecodeError as exc:
        out = ROOT / "data" / "agentic-review" / "ai-proposals-raw.txt"
        out.write_text(text, encoding="utf-8")
        raise SystemExit(f"model did not return JSON; raw output saved to {out}") from exc
    out = ROOT / "data" / "agentic-review" / "ai-proposals.jsonl"
    write_jsonl(out, proposals)
    print(f"wrote {len(proposals)} proposals to {out}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    build_parser = sub.add_parser("build", help="verify seed datasets and write JSONL")
    build_parser.add_argument("--dataset", default="all", choices=["all", *DATASETS.keys()])
    build_parser.add_argument("--r2-bin", default=None)
    build_parser.add_argument("--r2-source", default=str(DEFAULT_R2_SOURCE))
    build_parser.add_argument("--timeout", type=int, default=20)
    build_parser.add_argument("--dry-run", action="store_true")
    build_parser.set_defaults(func=build)

    propose_parser = sub.add_parser("propose", help="use an OpenAI-compatible model to propose pending rows")
    propose_parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o"))
    propose_parser.add_argument("--count", type=int, default=20)
    propose_parser.add_argument("--temperature", type=float, default=0.3)
    propose_parser.add_argument("--r2-source", default=str(DEFAULT_R2_SOURCE))
    propose_parser.set_defaults(func=propose)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
