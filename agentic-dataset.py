#!/usr/bin/env python3
"""Generate and verify radare2 training datasets with local evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
DEFAULT_R2_SOURCE = Path(os.environ.get("R2_SOURCE", str(ROOT.parent / "radare2")))
DEFAULT_R2_BIN_CANDIDATES = [
    os.environ.get("R2_BIN"),
    str(DEFAULT_R2_SOURCE / "b" / "binr" / "radare2" / "radare2"),
    str(DEFAULT_R2_SOURCE / "binr" / "radare2" / "radare2"),
    shutil.which("r2"),
    shutil.which("radare2"),
]
KNOWLEDGE_DIR = ROOT / "data" / "agentic-knowledge"
KNOWLEDGE_PATH = KNOWLEDGE_DIR / "knowledge.jsonl"
KNOWLEDGE_RUNS_DIR = KNOWLEDGE_DIR / "runs"
KNOWLEDGE_PENDING_PATH = KNOWLEDGE_DIR / "pending-human.jsonl"
KNOWLEDGE_INDEX_PATH = KNOWLEDGE_DIR / "index.json"
COMMANDS_DIR = ROOT / "data" / "agentic-commands"
COMMANDS_DB_PATH = COMMANDS_DIR / "commands.jsonl"
COMMANDS_TRAINING_PATH = COMMANDS_DIR / "verified.jsonl"
COMMANDS_INDEX_PATH = COMMANDS_DIR / "index.json"
COMMANDS_MEMORY_TOPICS_PATH = COMMANDS_DIR / "memory-topics.jsonl"
COMMANDS_KNOWLEDGE_TOPICS_PATH = COMMANDS_DIR / "knowledge-memory-topics.jsonl"
MEMORY_TOPICS_PATH = ROOT / "data" / "memory" / "topics.jsonl"
MEMORY_PATH = ROOT / "data" / "memory" / "memory.jsonl"
HUMAN_RESPONSES_PATH = ROOT / "data" / "agentic-review" / "human-responses.jsonl"
R2BUGS_PATH = ROOT / "R2BUGS.md"
R2BUGS_START = "<!-- agentic-r2bugs:start -->"
R2BUGS_END = "<!-- agentic-r2bugs:end -->"

DEFAULT_ONLINE_URLS = [
    "https://book.rada.re/",
    "https://book.rada.re/basic_commands/intro.html",
    "https://book.rada.re/analysis/code_analysis.html",
    "https://book.rada.re/scripting/r2js.html",
]

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
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}")
R2_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
R2R_TEST_CATEGORIES = ("cmd", "anal", "asm", "esil", "formats", "io", "json")
R2R_SKIP_TEST_FILES = {
    "cmd/cmd_system",
    "cmd/posixshell",
    "cmd/shell",
    "cmd/slow",
    "cmd/task",
    "io/http",
}
R2R_SAFE_URI_PREFIXES = ("malloc://", "hex://", "null://")
SOURCE_SCAN_ROOTS = ("libr/core", "libr/main", "libr/bin", "libr/io", "libr/util", "libr/include")
SOURCE_XREF_TARGETS = [
    {
        "term": "r_core_cmd",
        "topic": "xref.command_parser",
        "title": "Command parser API xrefs",
        "guidance": "Command parser APIs intentionally interpret separators, quotes, temporary seeks, and shell-style syntax for radare2 oneliners. Treat this as a bug only when command parsing is an undesired side effect across an API boundary; prefer r_core_call or call_at when literal command semantics are required.",
        "tags": ["xref", "command-parser", "command-parser-semantics"],
    },
    {
        "term": "r_core_call",
        "topic": "xref.safe_core_call",
        "title": "Core call API xrefs",
        "guidance": "Core call APIs are the safer comparison point for command execution because they avoid reparsing full command lines in many cases. Use these xrefs to learn safer command invocation patterns.",
        "tags": ["xref", "command-parser", "safe-api"],
    },
    {
        "term": "r_sys_cmd",
        "topic": "xref.shell_command",
        "title": "Shell command API xrefs",
        "guidance": "Shell command APIs must be checked against sandbox state and shell escaping. Audit whether file names, URLs, package names, or binary-controlled strings reach the shell.",
        "tags": ["xref", "shell", "injection-audit"],
    },
    {
        "term": "r_str_sanitize",
        "topic": "xref.sanitizers",
        "title": "String sanitizer xrefs",
        "guidance": "Sanitizer xrefs show how radare2 converts unsafe strings for names, shell use, or display. Audit whether the sanitizer matches the sink rather than assuming one filter is valid everywhere.",
        "tags": ["xref", "sanitizer", "defensive-api"],
    },
    {
        "term": "r_name_filter",
        "topic": "xref.name_filter",
        "title": "Name filter xrefs",
        "guidance": "Name filtering is relevant when binary-controlled symbols, flags, or generated script identifiers are emitted. Audit whether output can be reparsed as commands or scripts.",
        "tags": ["xref", "name-filter", "script-output"],
    },
    {
        "term": "r_cons_printf",
        "topic": "xref.console_output",
        "title": "Console output xrefs",
        "guidance": "Console output is usually display-only, but script-producing commands and star suffixes can turn printed strings into commands. Audit whether binary-controlled data is escaped before script output.",
        "tags": ["xref", "console", "script-output"],
    },
]
BUG_HUNT_PATTERNS = [
    {
        "name": "shell-command-injection",
        "regex": r"\br_sys_cmd(?:f|_str|_strf|dbg)?\b",
        "guidance": "Audit shell sinks for sandbox checks and shell escaping. Treat paths, URLs, package names, editor commands, and environment values as attacker-controlled until proven otherwise.",
        "tags": ["bug-hunt", "shell", "injection-audit"],
    },
    {
        "name": "script-output-escaping",
        "regex": r"\br_cons_printf\s*\(",
        "guidance": "Audit printed output that may be consumed by star commands, generated scripts, projects, or command replay. Binary-controlled strings should be filtered with the sanitizer matching the output language.",
        "tags": ["bug-hunt", "script-output", "escaping"],
    },
    {
        "name": "todo-memory-safety",
        "regex": r"\b(?:TODO|XXX)\b.*\b(?:leak|overflow|bounds|sanitize|crash|NULL|null|memory|uaf|free)\b",
        "guidance": "Audit the TODO/XXX note as a lead only. Confirm ownership, bounds, nullability, and test coverage before treating it as a bug.",
        "tags": ["bug-hunt", "memory-safety", "todo"],
    },
]


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


def jsonl_text(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)


def write_jsonl_if_changed(path: Path, rows: list[dict[str, Any]]) -> bool:
    text = jsonl_text(rows)
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL in {path}:{lineno}") from exc
            if isinstance(item, dict):
                rows.append(item)
    return rows


def rows_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id", "")): row for row in rows if row.get("id")}


def stable_hash(*parts: object, length: int = 16) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part).encode("utf-8", errors="replace"))
        h.update(b"\0")
    return h.hexdigest()[:length]


def safe_id_part(value: str) -> str:
    value = value.strip().replace("?", "_help")
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value.strip("._-") or "item"


def is_r2_uri_fixture(value: str) -> bool:
    return bool(R2_URI_RE.match(value))


def reuse_stable_verification_fields(path: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    old = rows_by_id(read_jsonl(path))
    for row in rows:
        prior = old.get(str(row.get("id", "")))
        if not prior:
            continue
        verification = row.get("verification", {})
        prior_verification = prior.get("verification", {})
        comparable = {k: v for k, v in verification.items() if k != "elapsed_ms"}
        prior_comparable = {k: v for k, v in prior_verification.items() if k != "elapsed_ms"}
        if comparable == prior_comparable and "elapsed_ms" in prior_verification:
            verification["elapsed_ms"] = prior_verification["elapsed_ms"]
    return rows


def strip_unstable_verification_fields(row: dict[str, Any]) -> dict[str, Any]:
    stable = copy.deepcopy(row)
    verification = stable.get("verification")
    if isinstance(verification, dict):
        verification.pop("elapsed_ms", None)
    return stable


def jsonl_equivalent_ignoring_unstable(path: Path, rows: list[dict[str, Any]]) -> bool:
    old_rows = read_jsonl(path)
    if len(old_rows) != len(rows):
        return False
    old_stable = [strip_unstable_verification_fields(row) for row in old_rows]
    new_stable = [strip_unstable_verification_fields(row) for row in rows]
    return old_stable == new_stable


def write_verified_jsonl(path: Path, rows: list[dict[str, Any]]) -> bool:
    if jsonl_equivalent_ignoring_unstable(path, rows):
        return False
    rows = reuse_stable_verification_fields(path, rows)
    return write_jsonl_if_changed(path, rows)


def fixture_path(entry: dict[str, Any], r2_source: Path) -> str:
    fixture = str(entry.get("fixture", "-"))
    if fixture in ("-", "--") or is_r2_uri_fixture(fixture):
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


def redact_email_like(match: re.Match[str]) -> str:
    value = match.group(0)
    local = value.split("@", 1)[0]
    if "-." in local:
        return value
    return "<email>"


def redact_emails(text: str) -> str:
    return EMAIL_RE.sub(redact_email_like, text)


def sanitize_text(text: str, r2_source: Path) -> str:
    sanitized = text
    roots = {str(r2_source)}
    try:
        roots.add(str(r2_source.resolve()))
    except OSError:
        pass
    for root in sorted(roots, key=len, reverse=True):
        sanitized = sanitized.replace(root + os.sep, "")
        sanitized = sanitized.replace(root, ".")
    sanitized = re.sub(r"/tmp/tmp[^\s'\"]+\.r2\.js", "<generated-r2js-script>", sanitized)
    sanitized = re.sub(r"/tmp/[^\s'\"`]+", "<tmp-path>", sanitized)
    sanitized = re.sub(r"/home/[^/\s]+/[^\s'\"`]*", "<home-path>", sanitized)
    sanitized = re.sub(r"/Users/[^/\s]+/[^\s'\"`]*", "<home-path>", sanitized)
    sanitized = redact_emails(sanitized)
    sanitized = re.sub(r"\b[pP]ancake\b", "radare2 contributor", sanitized)
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
    args.extend(str(arg) for arg in entry.get("r2_args", []))
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

GROWTH_HELP_TOPICS = HELP_TOPICS + [
    ("cmd.root", "?", "Top-level command syntax", ["libr/core/cmd.c"]),
    ("cmd.print", "p?", "Print and disassembly command family", ["libr/core/cmd_print.inc.c"]),
    ("cmd.print.disasm", "pd?", "Disassembly command family", ["libr/core/cmd_print.inc.c"]),
    ("cmd.print.hex", "px?", "Hexdump command family", ["libr/core/cmd_print.inc.c"]),
    ("cmd.analysis", "a?", "Analysis command family", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.analysis.function", "af?", "Function analysis command family", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.analysis.refs", "ax?", "Reference management command family", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.analysis.ops", "ao?", "Opcode analysis command family", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.graph", "ag?", "Graph generation command family", ["libr/core/cmd_anal.inc.c"]),
    ("cmd.info.imports", "ii?", "Import listing command family", ["libr/core/cmd_info.inc.c"]),
    ("cmd.info.sections", "iS?", "Section listing command family", ["libr/core/cmd_info.inc.c"]),
    ("cmd.info.strings", "iz?", "String listing command family", ["libr/core/cmd_info.inc.c"]),
    ("cmd.flags", "f?", "Flag command family", ["libr/core/cmd_flag.inc.c"]),
    ("cmd.flagspaces", "fs?", "Flag-space command family", ["libr/core/cmd_flag.inc.c"]),
    ("cmd.seek", "s?", "Seek command family", ["libr/core/cmd_seek.inc.c"]),
    ("cmd.open", "o?", "Open and IO command family", ["libr/core/cmd_open.inc.c"]),
    ("cmd.write", "w?", "Write command family", ["libr/core/cmd_write.inc.c"]),
    ("cmd.write.hex", "wx?", "Hex write command family", ["libr/core/cmd_write.inc.c"]),
    ("cmd.config", "e?", "Configuration command family", ["libr/core/cmd_eval.inc.c"]),
    ("cmd.plugins", "L?", "Plugin listing command family", ["libr/core/cmd_plugins.inc.c"]),
    ("cmd.comments", "CC?", "Comment command family", ["libr/core/cmd_meta.inc.c"]),
    ("cmd.sections", "S?", "Section command family", ["libr/core/cmd_section.inc.c"]),
    ("cmd.debug", "d?", "Debug command family", ["libr/core/cmd_debug.inc.c"]),
    ("cmd.debug.breakpoints", "db?", "Breakpoint command family", ["libr/core/cmd_debug.inc.c"]),
    ("cmd.debug.memory", "dm?", "Debug memory map command family", ["libr/core/cmd_debug.inc.c"]),
]

GROWTH_DOC_GLOBS = [
    "README.md",
    "USAGE.md",
    "DEVELOPERS.md",
    "AGENTS.md",
    "doc/*.md",
    "doc/pdb/*.md",
    "shlr/qjs/README.md",
    "test/README.md",
    "test/bins/*/README*",
]

GROWTH_EXPERIMENT_PLANS = [
    {
        "id": "workflow.esil.repeat_prefix.3aes",
        "topic": "command-composition.esil-repeat",
        "fixture": "malloc://16",
        "commands": [
            "e asm.arch=x86",
            "e asm.bits=32",
            "wx 404040",
            "pd 3",
            "aei",
            "aeim",
            "aer eax=0",
            "aer eip=0",
            "3aes",
            "aer eax",
            "aer eip",
        ],
        "checks": [{"type": "contains", "value": "inc eax"}, {"type": "contains", "value": "0x00000003"}],
        "question": "Why does `3aes` step three ESIL instructions in radare2?",
        "answer": "Radare2 command lines accept a numeric repeat prefix. `3aes` means run `aes` three times. The `aes` command is read as `a` for the analysis command family, `e` for ESIL, and `s` for ESIL step. This is equivalent to typing `aes; aes; aes`, and the verified example uses three `inc eax` bytes so both `eax` and `eip` end at `0x00000003` after `3aes`.",
        "source_refs": ["r2:?*", "libr/core/cmd_anal.inc.c"],
        "tags": ["workflow", "command-composition", "repeat-prefix", "esil", "aes"],
    },
    {
        "id": "workflow.oneliner.seek_grep.output",
        "topic": "command-composition.oneliner",
        "fixture": "test/bins/elf/hello_world",
        "commands": ["aaa", "afl~main", "pd 5 @ main", "p8 4 @ entry0", "izz~Hello"],
        "checks": [{"type": "contains", "value": "main"}, {"type": "contains", "value": "Hello"}],
        "question": "How do I build a radare2 oneliner with analysis, grep, and temporary seek syntax?",
        "answer": "Compose radare2 commands left to right: run an analysis command such as `aaa`, filter command output with `~`, and add `@ addr` to run a command at a temporary seek without changing the workflow intent. For example, `afl~main` filters functions to main-like rows, `pd 5 @ main` disassembles five instructions at `main`, and `izz~Hello` filters all strings for `Hello`.",
        "source_refs": ["r2:?*", "libr/core/cmd.c", "libr/core/cmd_anal.inc.c"],
        "tags": ["workflow", "command-composition", "oneliner", "grep", "temporary-seek"],
    },
    {
        "id": "workflow.elf.pdc.main",
        "topic": "decompilation.pdc",
        "fixture": "test/bins/elf/hello_world",
        "commands": ["aaa", "afl~main", "pdc @ main"],
        "checks": [{"type": "contains", "value": "main"}, {"type": "line_count_gte", "value": 4}],
        "question": "How can radare2 produce a built-in pseudocode view for an ELF main function without external decompiler plugins?",
        "answer": "Analyze first, locate main, then use `pdc @ main` as the built-in pseudocode fallback. Treat it as radare2-generated pseudocode and verify control flow against `pdf` when precision matters.",
        "source_refs": ["libr/core/cmd_print.inc.c", "libr/core/cmd_anal.inc.c"],
        "tags": ["workflow", "decompilation", "pdc", "elf"],
    },
    {
        "id": "workflow.elf.xref.string",
        "topic": "reverse.string_xref",
        "fixture": "test/bins/elf/hello_world",
        "commands": ["aaa", "iz~Hello", "axt @ str.Hello", "pdf @ main"],
        "checks": [{"type": "contains", "value": "Hello"}, {"type": "contains", "value": "main"}],
        "question": "How do I connect a visible string to the function that uses it in radare2?",
        "answer": "List strings with `iz`, use `axt @ str.<name>` to find xrefs, and inspect the caller with `pdf @ main` or the referenced function. The verified evidence should include both the string row and the caller xref.",
        "source_refs": ["libr/core/cmd_info.inc.c", "libr/core/cmd_anal.inc.c"],
        "tags": ["workflow", "xrefs", "strings", "elf"],
    },
    {
        "id": "workflow.pe.imports.mitigations",
        "topic": "pe.triage",
        "fixture": "test/bins/pe/normal.exe",
        "commands": ["iI", "ii", "iS~text", "izq"],
        "checks": [{"type": "line_count_gte", "value": 4}],
        "question": "What is a compact radare2 triage sequence for a PE executable?",
        "answer": "Use `iI` for format and mitigation metadata, `ii` for imports, `iS~text` for executable sections, and `izq` for quick strings. Keep claims tied to the printed rows because packed or malformed PE files can hide information.",
        "source_refs": ["libr/bin/p/bin_pe.c", "libr/core/cmd_info.inc.c"],
        "tags": ["workflow", "pe", "imports", "triage"],
    },
    {
        "id": "workflow.macho.checked_copy",
        "topic": "vulnerability.checked_copy",
        "fixture": "test/bins/mach0/strcpy-overflow",
        "commands": ["aaa", "i~canary,nx,pic", "afl~strcpy", "axt @ sym.imp.__strcpy_chk", "pdf @ main"],
        "checks": [{"type": "contains", "value": "__strcpy_chk"}, {"type": "contains", "value": "main"}],
        "question": "How should a radare2 workflow separate hardening facts from exploitability while triaging a checked-copy sample?",
        "answer": "Collect hardening fields with `i~canary,nx,pic`, locate fortified APIs with `afl~strcpy`, then inspect xrefs and `main`. Report observable facts first; do not infer exploitability until argument sizes and control paths are proven.",
        "source_refs": ["libr/core/cmd_info.inc.c", "libr/core/cmd_anal.inc.c"],
        "tags": ["workflow", "vulnerability-research", "macho", "mitigations"],
    },
    {
        "id": "workflow.firmware.arch.heuristic",
        "topic": "firmware.architecture",
        "fixture": "test/bins/elf/BLE_Beacon2.NRF51822_OTA.bin",
        "commands": ["i~format", "p8 16", "js: scripts/whatarch.r2.js"],
        "checks": [{"type": "contains", "value": "format   any"}, {"type": "contains", "value": "Best match:"}],
        "question": "How can an agent use radare2 to form a cautious architecture hypothesis for a raw firmware blob?",
        "answer": "Confirm the loader only knows `format any`, inspect reset-vector-like bytes, then run a scoring script such as `scripts/whatarch.r2.js`. The result is a hypothesis that must be checked against memory maps, vector tables, and chip context.",
        "source_refs": ["scripts/whatarch.r2.js", "libr/core/cmd_print.inc.c"],
        "tags": ["workflow", "firmware", "r2js", "architecture"],
    },
    {
        "id": "workflow.forensics.ext_mount",
        "topic": "forensics.filesystem",
        "fixture": "test/bins/fs/ext4.img",
        "commands": ["m ext2 / 0", "md /", "m"],
        "checks": [{"type": "contains", "value": "lost+found"}, {"type": "contains", "value": "root.txt"}],
        "question": "How can radare2 inspect an ext filesystem image without mounting it in the OS?",
        "answer": "Use radare2 filesystem commands: mount the image with `m ext2 / 0`, list with `md /`, and inspect mount state with `m`. A forensic answer should preserve offsets and hash exported files before conclusions.",
        "source_refs": ["libr/fs", "libr/core/cmd_mount.inc.c"],
        "tags": ["workflow", "forensics", "filesystem", "ext"],
    },
    {
        "id": "workflow.plugins.bin_list",
        "topic": "plugins.bin",
        "fixture": "--",
        "commands": ["L bin"],
        "checks": [{"type": "line_count_gte", "value": 5}],
        "question": "How do I ask radare2 which binary loader plugins are available?",
        "answer": "Run `L bin` from radare2. The output is the local plugin inventory, so training data should keep it as observed evidence rather than assuming every build has the same plugins.",
        "source_refs": ["libr/bin/p", "libr/core/cmd_plugins.inc.c"],
        "tags": ["workflow", "plugins", "bin"],
    },
    {
        "id": "workflow.crackme.bomb.phase_map",
        "topic": "challenge.crackme",
        "fixture": "test/bins/jmptbl/cmu_binary_bomb",
        "commands": ["aaa", "iz~phase", "afl~phase", "pdf @ main"],
        "checks": [{"type": "contains", "value": "phase"}, {"type": "contains", "value": "main"}],
        "question": "What is a safe first radare2 workflow for mapping phases in a crackme or binary bomb challenge?",
        "answer": "Start with non-destructive static analysis: run `aaa`, search strings for phase prompts, list phase-like functions, and inspect `main` to understand dispatch. Solve each phase only after tying prompts, comparisons, and control-flow evidence together.",
        "source_refs": ["test/bins/jmptbl/cmu_binary_bomb", "libr/core/cmd_anal.inc.c"],
        "tags": ["workflow", "challenge", "crackme", "strings", "xrefs"],
    },
    {
        "id": "workflow.crackme.pe_strings_imports",
        "topic": "challenge.crackme",
        "fixture": "test/bins/pe/plscrackme.exe",
        "commands": ["aaa", "iI", "ii", "izz", "aflq"],
        "checks": [{"type": "line_count_gte", "value": 8}],
        "question": "How can radare2 build an initial evidence pack for a PE crackme before patching or emulation?",
        "answer": "Collect loader metadata, imports, all strings, and discovered functions. Use that evidence to choose targets for xrefs and comparisons; do not patch until the validation path is identified.",
        "source_refs": ["test/bins/pe/plscrackme.exe", "libr/bin/p/bin_pe.c"],
        "tags": ["workflow", "challenge", "crackme", "pe"],
    },
]


def knowledge_messages(question: str, answer: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": "You are a radare2 knowledge-base builder. Prefer precise, source-grounded facts."},
        {"role": "user", "content": question},
        {"role": "assistant", "content": answer},
    ]


def build_help_knowledge(r2_bin: Path, r2_source: Path, timeout: int, seen: set[str] | None = None) -> list[dict[str, Any]]:
    rows = []
    for topic, command, title, refs in HELP_TOPICS:
        row_id = f"knowledge.{topic}"
        if seen is not None and row_id in seen:
            continue
        entry = {
            "id": row_id,
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
            "id": row_id,
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
    summary = redact_emails(summary)
    return summary, apis


def build_r2js_script_knowledge(r2_source: Path, seen: set[str] | None = None) -> list[dict[str, Any]]:
    scripts_dir = r2_source / "scripts"
    if not scripts_dir.is_dir():
        return []
    rows = []
    for path in sorted(scripts_dir.glob("*.r2.js")):
        row_id = "knowledge.r2js.script." + path.stem.replace(".", "_")
        if seen is not None and row_id in seen:
            continue
        summary, apis = summarize_r2js_script(path)
        if not apis:
            continue
        ref = relative_to_r2_source(str(path), r2_source)
        answer = f"`{ref}` is an r2js script. Summary: {summary}. Observed r2 APIs: {', '.join('r2.' + api for api in apis)}."
        rows.append({
            "id": row_id,
            "kind": "agentic_knowledge",
            "topic": "r2js.script",
            "source_refs": [ref],
            "messages": knowledge_messages(f"What radare2 JavaScript APIs does `{ref}` demonstrate?", answer),
            "tags": ["r2js", "script", *apis],
        })
    return rows


def compact_text(text: str, r2_source: Path, limit: int = 1800) -> str:
    text = sanitize_text(text, r2_source)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return output_excerpt(text, limit)


def extract_doc_signal(text: str, r2_source: Path, limit: int = 1400) -> str:
    text = sanitize_text(text, r2_source)
    wanted = re.compile(
        r"(`[^`]+`|\br2\b|radare2|command|plugin|analysis|debug|decompil|forensic|firmware|"
        r"xref|strings?|sections?|imports?|exports?|filesystem|r2js|script|workflow|use |run )",
        re.IGNORECASE,
    )
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^\d+(\.\d+){0,4}\.?\s+", stripped):
            continue
        if len(stripped) > 220:
            stripped = stripped[:220].rstrip() + "..."
        if stripped.startswith("#") or wanted.search(stripped):
            lines.append(stripped)
        if len("\n".join(lines)) >= limit:
            break
    if not lines:
        lines = [line.strip() for line in text.splitlines() if line.strip()[:1] != "#"][:8]
    return compact_text("\n".join(lines), r2_source, limit)


def html_to_text(text: str) -> str:
    main = re.search(r"(?is)<main[^>]*>(.*?)</main>", text) or re.search(r"(?is)<article[^>]*>(.*?)</article>", text)
    if main:
        text = main.group(1)
    text = re.sub(r"(?is)<(script|style|nav|header|footer|aside).*?</\1>", "\n", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|section|article|h[1-6]|li|tr|pre|code)>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text)


def knowledge_row(
    row_id: str,
    topic: str,
    question: str,
    answer: str,
    source_refs: list[str],
    r2_source: Path,
    tags: list[str] | None = None,
    verification: dict[str, Any] | None = None,
    title: str | None = None,
    kind: str = "agentic_knowledge",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": row_id,
        "kind": kind,
        "topic": topic,
        "source_refs": [sanitize_text(ref, r2_source) for ref in source_refs],
        "messages": knowledge_messages(
            sanitize_text(question, r2_source),
            sanitize_text(answer, r2_source),
        ),
    }
    if tags:
        row["tags"] = tags
    if verification:
        row["verification"] = verification
    if title:
        row["title"] = sanitize_text(title, r2_source)
    return row


def human_answer_row_id(pending_id: str) -> str:
    return "knowledge.human." + safe_id_part(pending_id)


def human_responses_by_pending_id() -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for response in read_jsonl(HUMAN_RESPONSES_PATH):
        pending_id = str(response.get("id", ""))
        if not pending_id:
            continue
        action = str(response.get("action", ""))
        if action in {"answered", "dropped"}:
            latest[pending_id] = response
    return latest


def human_suppressed_pending_ids() -> set[str]:
    return set(human_responses_by_pending_id())


def human_response_knowledge_rows(r2_source: Path, responses: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if responses is None:
        response_map = human_responses_by_pending_id()
        responses = list(response_map.values())
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for response in responses:
        pending_id = str(response.get("id", ""))
        answer = str(response.get("human_answer", "")).strip()
        if not pending_id or response.get("action") != "answered" or not answer:
            continue
        row_id = human_answer_row_id(pending_id)
        if row_id in seen_ids:
            continue
        original = response.get("original", {}) if isinstance(response.get("original"), dict) else {}
        refs = []
        for ref in original.get("source_refs", []):
            refs.append(str(ref))
        if response.get("source_pending"):
            refs.append(str(response["source_pending"]))
        question = str(response.get("question") or original.get("question") or pending_id)
        rows.append(knowledge_row(
            row_id,
            "human.pending_answer",
            question,
            "Human-reviewed answer for a previously pending agentic task:\n" + answer,
            refs,
            r2_source,
            tags=["human-review", str(response.get("kind") or original.get("kind") or "pending")],
            title="Human answer for " + pending_id,
        ))
        seen_ids.add(row_id)
    return rows


def existing_knowledge_ids() -> set[str]:
    ids = {str(row.get("id")) for row in read_jsonl(KNOWLEDGE_PATH) if row.get("id")}
    if KNOWLEDGE_RUNS_DIR.is_dir():
        for path in KNOWLEDGE_RUNS_DIR.glob("*.jsonl"):
            ids.update(str(row.get("id")) for row in read_jsonl(path) if row.get("id"))
    ids.update(human_suppressed_pending_ids())
    return ids


def assistant_text(row: dict[str, Any]) -> str:
    for message in row.get("messages", []):
        if isinstance(message, dict) and message.get("role") == "assistant":
            return str(message.get("content", ""))
    return ""


def set_assistant_text(row: dict[str, Any], content: str) -> None:
    for message in row.get("messages", []):
        if isinstance(message, dict) and message.get("role") == "assistant":
            message["content"] = content
            return


def primary_source_ref(row: dict[str, Any]) -> str:
    refs = row.get("source_refs", [])
    if isinstance(refs, list) and refs:
        return str(refs[0])
    return ""


def normalized_knowledge_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"0x[0-9a-f]+", "0x", text)
    text = re.sub(r"\b\d+\b", "#", text)
    text = re.sub(r"[`'\"\\]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def navigation_line_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if re.match(r"^\s*\d+(\.\d+){0,4}\.?\s+\S", line))


def code_line_density(text: str) -> float:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return 0.0
    code_lines = 0
    for line in lines:
        if line.startswith(("#include", "typedef", "static ", "return ", "if (", "for (", "while (", "case ", "R_")):
            code_lines += 1
        elif line.endswith((";", "{", "}")) or "->" in line:
            code_lines += 1
    return code_lines / len(lines)


def compact_plugin_answer(answer: str) -> str:
    first = answer.split("Relevant source excerpt:", 1)[0].strip()
    if first:
        return first + " This row records plugin identity only; detailed behavior should be learned from focused command evidence or concise source documentation."
    return answer


def knowledge_fingerprint(row: dict[str, Any]) -> str:
    topic = str(row.get("topic", ""))
    kind = str(row.get("kind", ""))
    refs = row.get("source_refs", [])
    ref_hint = ""
    if isinstance(refs, list) and refs:
        ref_hint = str(refs[0])
    text = normalized_knowledge_text(assistant_text(row))[:1600]
    if topic == "plugin.source":
        return stable_hash(topic, text)
    if topic == "fixture.triage":
        return stable_hash(topic)
    if topic.startswith("online."):
        return stable_hash(topic, text[:900])
    return stable_hash(kind, topic, ref_hint, text)


def cleanup_knowledge_row(row: dict[str, Any]) -> dict[str, Any] | None:
    row = copy.deepcopy(row)
    topic = str(row.get("topic", ""))
    answer = assistant_text(row)
    if not str(row.get("id", "")):
        return None
    if topic == "fixture.triage":
        return None
    if topic.startswith("online.") and navigation_line_count(answer) > 24:
        return None
    if topic == "plugin.source" and "Relevant source excerpt:" in answer:
        answer = compact_plugin_answer(answer)
        set_assistant_text(row, answer)
    if topic == "plugin.source" and code_line_density(answer) > 0.25:
        return None
    if topic == "xref.command_parser":
        answer = answer.replace('Command parser APIs interpret separators, quotes, temporary seeks, and shell escapes. Audit variable-controlled uses carefully and prefer r_core_call or call_at style APIs when a literal command is not required.', 'Command parser APIs intentionally interpret separators, quotes, temporary seeks, and shell-style syntax for radare2 oneliners. Treat this as a bug only when command parsing is an undesired side effect across an API boundary; prefer r_core_call or call_at when literal command semantics are required.')
        set_assistant_text(row, answer)
        tags = row.get("tags", [])
        if isinstance(tags, list):
            row["tags"] = ["command-parser-semantics" if tag == "injection-audit" else tag for tag in tags]
    if topic.startswith("audit."):
        return None
    if topic.startswith("xref."):
        refs = row.get("source_refs", [])
        if isinstance(refs, list) and any(str(ref).startswith("libr/") for ref in refs):
            return None
        if "`libr/" in answer or "Representative xrefs:" in answer:
            return None
    if len(normalized_knowledge_text(answer)) < 50 and not topic.startswith("human."):
        return None
    row["content_fingerprint"] = knowledge_fingerprint(row)
    return row


def knowledge_category_limits() -> dict[str, int]:
    return {
        "human-reviewed": int(os.environ.get("AGENTIC_MAX_HUMAN_ROWS", "1000")),
        "online-radare2-docs": int(os.environ.get("AGENTIC_MAX_ONLINE_ROWS", "12")),
        "r2-command-help": int(os.environ.get("AGENTIC_MAX_HELP_ROWS", "80")),
        "radare2-command-grammar": int(os.environ.get("AGENTIC_MAX_COMMAND_GRAMMAR_ROWS", "240")),
        "r2js": int(os.environ.get("AGENTIC_MAX_R2JS_ROWS", "80")),
        "radare2-plugin-source": int(os.environ.get("AGENTIC_MAX_PLUGIN_SOURCE_ROWS", "64")),
        "radare2-source-docs": int(os.environ.get("AGENTIC_MAX_SOURCE_DOC_ROWS", "80")),
        "radare2-source-xrefs": int(os.environ.get("AGENTIC_MAX_SOURCE_XREF_ROWS", "160")),
        "verified-radare2-workflows": int(os.environ.get("AGENTIC_MAX_R2R_TEST_ROWS", "240")),
        "verified-workflows": int(os.environ.get("AGENTIC_MAX_WORKFLOW_ROWS", "80")),
    }


def dedupe_knowledge_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    category_counts: dict[str, int] = {}
    r2r_source_counts: dict[str, int] = {}
    category_limits = knowledge_category_limits()
    r2r_max_rows_per_source = int(os.environ.get("AGENTIC_R2R_MAX_ROWS_PER_SOURCE", "2"))
    for row in rows:
        cleaned = cleanup_knowledge_row(row)
        if not cleaned:
            continue
        category = knowledge_category(cleaned)
        if category_counts.get(category, 0) >= category_limits.get(category, 1_000_000):
            continue
        if category == "verified-radare2-workflows" and r2r_max_rows_per_source > 0:
            source_ref = primary_source_ref(cleaned)
            if source_ref and r2r_source_counts.get(source_ref, 0) >= r2r_max_rows_per_source:
                continue
        row_id = str(cleaned.get("id", ""))
        fingerprint = str(cleaned.get("content_fingerprint", ""))
        if row_id in seen_ids or fingerprint in seen_fingerprints:
            continue
        deduped.append(cleaned)
        seen_ids.add(row_id)
        seen_fingerprints.add(fingerprint)
        category_counts[category] = category_counts.get(category, 0) + 1
        if category == "verified-radare2-workflows":
            source_ref = primary_source_ref(cleaned)
            if source_ref:
                r2r_source_counts[source_ref] = r2r_source_counts.get(source_ref, 0) + 1
    return deduped


def merge_rows(existing: list[dict[str, Any]], new_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return dedupe_knowledge_rows(existing + new_rows)


def merge_pending_rows(existing: list[dict[str, Any]], new_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = list(existing)
    seen = {str(row.get("id", "")) for row in merged if row.get("id")}
    for row in new_rows:
        row_id = str(row.get("id", ""))
        if row_id and row_id not in seen:
            merged.append(row)
            seen.add(row_id)
    return merged


def next_run_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = KNOWLEDGE_RUNS_DIR / f"{stamp}.jsonl"
    if not path.exists():
        return path
    for idx in range(1, 1000):
        candidate = KNOWLEDGE_RUNS_DIR / f"{stamp}-{idx}.jsonl"
        if not candidate.exists():
            return candidate
    raise RuntimeError("cannot allocate agentic knowledge run path")


def knowledge_category(row: dict[str, Any]) -> str:
    topic = str(row.get("topic") or row.get("kind") or "uncategorized")
    if topic.startswith("grammar."):
        return "radare2-command-grammar"
    if topic.startswith("cmd."):
        return "r2-command-help"
    if topic.startswith("source."):
        return "radare2-source-docs"
    if topic.startswith("plugin."):
        return "radare2-plugin-source"
    if topic.startswith("online."):
        return "online-radare2-docs"
    if topic.startswith("human."):
        return "human-reviewed"
    if topic.startswith("xref."):
        return "radare2-source-xrefs"
    if topic.startswith("r2r."):
        return "verified-radare2-workflows"
    if row.get("kind") == "agentic_experiment":
        return "verified-workflows"
    return topic.split(".", 1)[0]


def count_by_category(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        category = knowledge_category(row)
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def row_message_content(row: dict[str, Any], role: str) -> str:
    for message in row.get("messages", []):
        if isinstance(message, dict) and message.get("role") == role:
            return str(message.get("content", "")).strip()
    return ""


def clipped_print_text(text: str, limit: int) -> str:
    text = text.strip()
    if limit > 0 and len(text) > limit:
        return text[:limit].rstrip() + "\n[truncated]"
    return text


def print_indented_text(text: str, indent: str, limit: int) -> None:
    text = clipped_print_text(text, limit)
    if not text:
        print(indent + "<empty>")
        return
    for line in text.splitlines():
        print(indent + line)


def verification_check_summary(checks: Any) -> str:
    if not isinstance(checks, list) or not checks:
        return ""
    parts = []
    for check in checks[:4]:
        if not isinstance(check, dict):
            continue
        ctype = str(check.get("type", "check"))
        value = str(check.get("value", check.get("path", ""))).replace("\n", " ")
        passed = "ok" if check.get("passed") else "pending"
        parts.append(f"{ctype}({value})={passed}" if value else f"{ctype}={passed}")
    if len(checks) > 4:
        parts.append(f"+{len(checks) - 4} more")
    return "; ".join(parts)


def print_knowledge_row_content(row: dict[str, Any]) -> None:
    limit = int(os.environ.get("AGENTIC_PRINT_ROW_CONTENT_LIMIT", "4000"))
    refs = row.get("source_refs", [])
    if isinstance(refs, list) and refs:
        print("    sources: " + ", ".join(map(str, refs)))
    if row.get("title"):
        print(f"    title: {row.get('title')}")
    question = row_message_content(row, "user")
    answer = row_message_content(row, "assistant")
    print("    question:")
    print_indented_text(question, "      ", limit)
    print("    answer:")
    print_indented_text(answer, "      ", limit)
    verification = row.get("verification")
    if isinstance(verification, dict):
        status = verification.get("status")
        returncode = verification.get("returncode")
        details = []
        if status is not None:
            details.append(f"status={status}")
        if returncode is not None:
            details.append(f"returncode={returncode}")
        check_summary = verification_check_summary(verification.get("checks"))
        if check_summary:
            details.append(f"checks={check_summary}")
        if details:
            print("    verification: " + "; ".join(details))
        command_line = verification.get("command_line")
        if isinstance(command_line, list) and command_line:
            print("    command: " + " ".join(map(str, command_line)))
        if verification.get("output_excerpt"):
            print("    output excerpt:")
            print_indented_text(str(verification.get("output_excerpt", "")), "      ", min(limit, 1200))


def print_new_knowledge_rows(rows: list[dict[str, Any]], pending_rows: list[dict[str, Any]]) -> None:
    if rows:
        print("knowledge new rows:")
        for row in rows:
            refs = row.get("source_refs", [])
            ref = ""
            if isinstance(refs, list) and refs:
                ref = f" [{refs[0]}]"
            print(f"  + {knowledge_category(row)} {row.get('id', '<missing-id>')}: {row.get('topic', row.get('kind', ''))}{ref}")
            print_knowledge_row_content(row)
        counts = ", ".join(f"{name}={count}" for name, count in count_by_category(rows).items())
        print(f"knowledge new categories: {counts}")
    else:
        print("knowledge new rows: none (all current candidates were duplicates, capped, unsafe, or below the quality threshold)")
    if pending_rows:
        print("knowledge pending rows:")
        for row in pending_rows:
            print(f"  ? {row.get('kind', 'pending')} {row.get('id', '<missing-id>')}: {row.get('reason', '')}")


def promote_knowledge_rows(rows: list[dict[str, Any]]) -> int:
    clean_run_shards()
    existing = merge_rows(read_jsonl(KNOWLEDGE_PATH), [])
    existing_ids = {str(row.get("id")) for row in existing if row.get("id")}
    existing_fingerprints = {str(row.get("content_fingerprint")) for row in existing if row.get("content_fingerprint")}
    aggregate = merge_rows(existing, dedupe_knowledge_rows(rows))
    new_rows = []
    for row in aggregate:
        row_id = str(row.get("id", ""))
        fingerprint = str(row.get("content_fingerprint", ""))
        if row_id not in existing_ids and fingerprint not in existing_fingerprints:
            new_rows.append(row)
    if not new_rows:
        return 0
    write_jsonl(next_run_path(), new_rows)
    write_jsonl_if_changed(KNOWLEDGE_PATH, aggregate)
    clean_run_shards(aggregate)
    return len(new_rows)


def clean_run_shards(allowed_rows: list[dict[str, Any]] | None = None) -> None:
    if not KNOWLEDGE_RUNS_DIR.is_dir():
        return
    allowed_ids: set[str] | None = None
    allowed_fingerprints: set[str] | None = None
    if allowed_rows is not None:
        allowed_ids = {str(row.get("id")) for row in allowed_rows if row.get("id")}
        allowed_fingerprints = {str(row.get("content_fingerprint")) for row in allowed_rows if row.get("content_fingerprint")}
    for path in sorted(KNOWLEDGE_RUNS_DIR.glob("*.jsonl")):
        rows = dedupe_knowledge_rows(read_jsonl(path))
        if allowed_ids is not None and allowed_fingerprints is not None:
            rows = [
                row for row in rows
                if str(row.get("id", "")) in allowed_ids or str(row.get("content_fingerprint", "")) in allowed_fingerprints
            ]
        if not rows:
            try:
                path.unlink()
            except OSError:
                pass
            continue
        write_jsonl_if_changed(path, rows)


def write_knowledge_outputs(new_rows: list[dict[str, Any]], pending_rows: list[dict[str, Any]], args: argparse.Namespace) -> tuple[int, int, list[dict[str, Any]], Path | None]:
    clean_run_shards()
    existing = merge_rows(read_jsonl(KNOWLEDGE_PATH), [])
    existing_ids = {str(row.get("id")) for row in existing if row.get("id")}
    existing_fingerprints = {str(row.get("content_fingerprint")) for row in existing if row.get("content_fingerprint")}
    aggregate = merge_rows(existing, dedupe_knowledge_rows(new_rows))
    accepted_new = []
    for row in aggregate:
        row_id = str(row.get("id", ""))
        fingerprint = str(row.get("content_fingerprint", ""))
        if row_id not in existing_ids and fingerprint not in existing_fingerprints:
            accepted_new.append(row)
    run_path = None
    if accepted_new:
        run_path = next_run_path()
        write_jsonl(run_path, accepted_new)
    write_jsonl_if_changed(KNOWLEDGE_PATH, aggregate)
    clean_run_shards(aggregate)
    pending = merge_pending_rows(
        filter_suppressed_pending_rows(read_jsonl(KNOWLEDGE_PENDING_PATH)),
        filter_suppressed_pending_rows(pending_rows),
    )
    write_jsonl_if_changed(KNOWLEDGE_PENDING_PATH, pending)
    index = {
        "knowledge_rows": len(aggregate),
        "last_new_rows": len(accepted_new),
        "last_new_by_category": count_by_category(accepted_new),
        "aggregate_by_category": count_by_category(aggregate),
        "last_pending_rows": len(pending_rows),
        "online_mode": args.online,
        "growth_budget": args.growth_budget,
        "section_budget": args.section_budget,
        "discover_fixtures": args.discover_fixtures,
        "category_limits": knowledge_category_limits(),
        "quality_policy": [
            "dedupe by id and content_fingerprint",
            "prune generic fixture.triage rows unless explicitly retained elsewhere",
            "reject navigation-heavy online pages",
            "keep plugin rows as concise symbol summaries, not raw source dumps",
            "source docs use signal extraction instead of full-file excerpts",
            "mine `?*` command grammar into focused command-construction rows",
            "cap verified r2r workflow rows per source file to avoid low-entropy growth",
            "source bug-hunt findings are written to R2BUGS.md, not training knowledge rows"
        ],
        "growth_sections": [
            "human-reviewed pending answers",
            "radare2 command help",
            "radare2 command grammar from `?*`",
            "verified workflows and challenges",
            "radare2 source xrefs",
            "source bug-hunt report in R2BUGS.md",
            "verified radare2 workflows discovered from test/db",
            "radare2 source documentation",
            "radare2 plugin source",
            "local radare2 book",
            "online radare2/book resources",
            "r2js scripts",
        ],
        "path_policy": "fixtures and source refs are relative to R2_SOURCE; local home/temp paths are sanitized",
    }
    KNOWLEDGE_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    KNOWLEDGE_INDEX_PATH.write_text(json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return len(accepted_new), len(aggregate), accepted_new, run_path


def verification_summary(verification: Verification, r2_source: Path, r2_bin: Path) -> dict[str, Any]:
    sanitized_output = sanitize_text(verification.output, r2_source)
    return {
        "status": verification.status,
        "returncode": verification.returncode,
        "command_line": sanitize_command_line(verification.command_line, r2_source, r2_bin),
        "checks": verification.checks,
        "output_sha256": hashlib.sha256(sanitized_output.encode("utf-8")).hexdigest(),
        "output_excerpt": output_excerpt(sanitized_output, 1800),
    }


def command_grammar_verification(verification: Verification, r2_source: Path, r2_bin: Path, checks: list[dict[str, Any]], excerpt: str) -> dict[str, Any]:
    return {
        "status": verification.status,
        "returncode": verification.returncode,
        "elapsed_ms": verification.elapsed_ms,
        "command_line": sanitize_command_line(verification.command_line, r2_source, r2_bin),
        "checks": checks,
        "output_excerpt": output_excerpt(excerpt, 1800),
    }


def command_grammar_excerpt(output: str, needles: list[str], r2_source: Path, limit: int = 1400) -> str:
    lines: list[str] = []
    clean = sanitize_text(clean_output(output), r2_source)
    lowered_needles = [needle.lower() for needle in needles]
    current_usage = ""
    for line in clean.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Usage:"):
            current_usage = stripped
        haystack = stripped.lower()
        if any(needle in haystack for needle in lowered_needles):
            if current_usage and (not lines or lines[-1] != current_usage):
                lines.append(current_usage)
            lines.append(stripped)
        if len("\n".join(lines)) >= limit:
            break
    if not lines:
        lines = [line.strip() for line in clean.splitlines() if line.strip()][:12]
    return output_excerpt("\n".join(lines), limit)


def parse_command_grammar_blocks(output: str, r2_source: Path) -> list[tuple[str, list[str]]]:
    clean = sanitize_text(clean_output(output), r2_source)
    blocks: list[tuple[str, list[str]]] = []
    current: list[str] = []
    for line in clean.splitlines():
        stripped = line.rstrip()
        if stripped.startswith("Usage:"):
            if current:
                blocks.append((current[0], current[:80]))
            current = [stripped]
            continue
        if not current:
            continue
        if not stripped:
            continue
        if stripped.startswith("|") or stripped.endswith(":") or stripped.startswith(("modifier:", "endmodifier:", "column:", "Examples:")):
            current.append(stripped)
        elif len(current) < 8:
            current.append(stripped)
    if current:
        blocks.append((current[0], current[:80]))
    return blocks


def command_grammar_token(usage_line: str) -> str:
    body = usage_line.removeprefix("Usage:").strip()
    if not body:
        return "command"
    token = body.split()[0].strip("[]")
    return token or "command"


def command_grammar_subject(usage_line: str) -> tuple[str, str, str]:
    body = usage_line.removeprefix("Usage:").strip()
    if body.startswith("%["):
        return (
            "environment",
            "environment variable commands",
            "How do `%` commands read and set environment variables inside radare2?",
        )
    if body.startswith("(foo"):
        return (
            "macros",
            "command macros",
            "How do radare2 command macros group and replay command sequences?",
        )
    if body.startswith("[.:"):
        return (
            "composition",
            "command composition modifiers",
            "How do repeat counts, output modes, grep, pipes, and temporary seeks compose radare2 one-liners?",
        )
    if body.startswith("-"):
        return (
            "dash-aliases",
            "dash command aliases",
            "How do dash-prefixed convenience commands map to common radare2 actions?",
        )
    token = command_grammar_token(usage_line)
    subject_id = safe_id_part(token)
    return (
        subject_id,
        f"`{token}` command family",
        f"How is the `{token}` radare2 command family constructed?",
    )


def command_grammar_focus_specs() -> list[dict[str, Any]]:
    return [
        {
            "id": "repeat-prefix-esil-step",
            "topic": "grammar.command.repeat-prefix",
            "title": "Repeat prefixes and ESIL stepping",
            "question": "Why does `3aes` mean three ESIL steps in radare2?",
            "answer": "A leading decimal number repeats the following radare2 command. `3aes` is parsed as repeat count `3` plus command `aes`; `a` enters the analysis family, `e` selects ESIL, and `s` performs one ESIL step. Use this pattern whenever a command should be repeated without writing `cmd;cmd;cmd`.",
            "needles": ["prefix with number", "repeat command", "Append '?' to any char command"],
            "checks": [{"type": "contains", "value": "Prefix with number to repeat command"}],
            "tags": ["command-grammar", "repeat-prefix", "esil", "aes"],
        },
        {
            "id": "oneliner-shape",
            "topic": "grammar.command.oneliner",
            "title": "Radare2 oneliner shape",
            "question": "What is the general shape of a radare2 oneliner?",
            "answer": "A radare2 oneliner is a command plus optional composition operators: repeat prefix, output mode suffixes such as `*` or `j`, backtick substitution, temporary seek with `@`, grep with `~`, pipe or redirect. This is why compact commands like `pd 5 @ main`, `afl~main`, and `3aes` are valid building blocks for larger workflows.",
            "needles": ["[.:\"][#]<cmd>", "@ 0x1024", "~word", "`pdi~push:0[0]`"],
            "checks": [{"type": "contains", "value": "temporary seek"}, {"type": "contains", "value": "grep for lines matching word"}],
            "tags": ["command-grammar", "oneliner", "temporary-seek", "grep"],
        },
        {
            "id": "iterators",
            "topic": "grammar.command.iterators",
            "title": "Radare2 iterators",
            "question": "How do `@@` and `@@@` extend radare2 commands across many offsets?",
            "answer": "The `@@` operator repeats a command over a list of offsets or objects, such as flags, functions, instructions, sections, or search hits. The `@@@` form carries offset and size pairs for commands that need both. Use these for scalable one-liners instead of manually repeating seeks and commands.",
            "needles": ["@@=1 2 3", "run the previous command", "@@@", "functions matching"],
            "checks": [{"type": "contains", "value": "@@=1 2 3"}, {"type": "contains", "value": "@@@"}],
            "tags": ["command-grammar", "iterator", "oneliner"],
        },
        {
            "id": "output-modes",
            "topic": "grammar.command.output-modes",
            "title": "Radare2 output modes",
            "question": "How do `*`, `j`, and `~` change radare2 command output?",
            "answer": "Many radare2 commands accept suffixes or companion forms for output mode. `*` asks for r2-script output, `j` asks for JSON when supported, and `~` filters output in the console. Training examples should preserve those forms because they are how agents build scripts, parse data, and keep one-liners small.",
            "needles": ["output of command in r2 script format", "output of command in JSON format", "grep for lines matching word"],
            "checks": [{"type": "contains", "value": "output of command in JSON format"}],
            "tags": ["command-grammar", "output-mode", "json", "grep"],
        },
    ]


def build_command_grammar_knowledge(r2_bin: Path, r2_source: Path, timeout: int, seen: set[str], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    if limit <= 0:
        return rows, pending
    entry = {
        "id": "knowledge.command_grammar.full_help_probe",
        "kind": "reasoning_task",
        "fixture": "--",
        "starter_commands": ["?*"],
        "checks": [
            {"type": "contains", "value": "Append '?' to any char command"},
            {"type": "contains", "value": "Prefix with number to repeat command"},
        ],
        "answer": "",
        "question": "",
    }
    verification = run_entry(entry, r2_bin, r2_source, timeout)
    if not verification.ok:
        pending.append(growth_pending("knowledge.command_grammar.full_help_probe", "command-grammar", "Run `?*` to discover the radare2 command grammar", verification, r2_source, ["r2:?*"]))
        return rows, pending

    output = verification.output
    for spec in command_grammar_focus_specs():
        if len(rows) >= limit:
            break
        row_id = "knowledge.command_grammar." + safe_id_part(str(spec["id"]))
        if row_id in seen:
            continue
        ok, checks, _reason = evaluate_checks(output, list(spec["checks"]))
        if not ok:
            continue
        excerpt = command_grammar_excerpt(output, list(spec["needles"]), r2_source)
        answer = f"{spec['answer']}\n\nEvidence from `?*`:\n{excerpt}"
        rows.append(knowledge_row(
            row_id,
            str(spec["topic"]),
            str(spec["question"]),
            answer,
            ["r2:?*"],
            r2_source,
            tags=list(spec["tags"]),
            verification=command_grammar_verification(verification, r2_source, r2_bin, checks, excerpt),
            title=str(spec["title"]),
        ))
        seen.add(row_id)

    for usage_line, block in parse_command_grammar_blocks(output, r2_source):
        if len(rows) >= limit:
            break
        subject_id, subject, question = command_grammar_subject(usage_line)
        row_id = "knowledge.command_grammar.block." + subject_id + "." + stable_hash(usage_line, length=8)
        if row_id in seen:
            continue
        excerpt = output_excerpt("\n".join(block), 1400)
        topic = "grammar.command." + subject_id
        answer = (
            f"The full `?*` grammar describes {subject} and the variants accepted by the command parser. "
            f"Read the leftmost letters as the command family and the following letters, suffixes, or arguments as refinements. "
            f"When building one-liners, combine the family with repeat prefixes, `@` temporary seeks, `~` grep, `j` JSON output, `*` script output, or iterators when the family supports them.\n\n"
            f"`?*` excerpt:\n{excerpt}"
        )
        checks = [{"type": "contains", "value": usage_line[:120]}]
        ok, checked, _reason = evaluate_checks(output, checks)
        if not ok:
            continue
        rows.append(knowledge_row(
            row_id,
            topic,
            question,
            answer,
            ["r2:?*"],
            r2_source,
            tags=["command-grammar", "r2cmd", subject_id],
            verification=command_grammar_verification(verification, r2_source, r2_bin, checked, excerpt),
            title=subject,
        ))
        seen.add(row_id)
    return rows, pending


COMMAND_ROOT_MEANINGS = {
    "?": "help, numeric expressions, and command introspection",
    "%": "environment variables",
    "!": "system command bridge",
    "#": "comments and hashbang script dispatch",
    "$": "aliases and numeric variables",
    "(": "command macros",
    ".": "script execution, command replay, or current-item modifier",
    ":": "I/O command bridge",
    "=": "remote sessions and servers",
    "/": "search",
    "a": "analysis",
    "b": "block size",
    "C": "comments and metadata",
    "d": "debugger",
    "e": "eval configuration",
    "f": "flags",
    "i": "binary information",
    "k": "key-value database",
    "L": "plugins",
    "m": "mounts and filesystems",
    "o": "open files and I/O backends",
    "p": "print and disassembly",
    "s": "seek",
    "S": "sections",
    "t": "types",
    "T": "text log",
    "u": "undo or host information",
    "w": "write and patch",
    "x": "hex dump alias",
    "y": "yank/copy buffer",
    "z": "zignatures",
}

COMMAND_CONTEXT_LETTER_MEANINGS = {
    ("a", "a"): "automatic analysis",
    ("aa", "a"): "deeper automatic analysis",
    ("a", "e"): "ESIL",
    ("ae", "s"): "step one ESIL instruction",
    ("a", "f"): "function",
    ("af", "a"): "analyze function",
    ("af", "b"): "basic blocks",
    ("af", "l"): "list",
    ("af", "n"): "name",
    ("af", "s"): "function size",
    ("af", "x"): "cross references",
    ("afl", "j"): "JSON output",
    ("afl", "q"): "quiet output",
    ("afl", "x"): "xref-oriented listing",
    ("a", "g"): "graph",
    ("a", "o"): "opcode",
    ("a", "r"): "registers",
    ("a", "s"): "symbols",
    ("a", "x"): "cross references",
    ("ax", "t"): "references to an address",
    ("ax", "f"): "references from an address",
    ("C", "C"): "comments",
    ("d", "b"): "breakpoints",
    ("d", "c"): "continue",
    ("d", "m"): "memory maps",
    ("d", "r"): "registers",
    ("d", "s"): "step",
    ("f", "s"): "flag spaces",
    ("i", "i"): "imports",
    ("i", "E"): "exports",
    ("i", "S"): "sections",
    ("i", "z"): "strings",
    ("i", "I"): "file information",
    ("p", "8"): "raw bytes as hexpairs",
    ("p", "c"): "bytes as code or C output",
    ("p", "d"): "disassembly",
    ("p", "f"): "format data",
    ("p", "i"): "instructions",
    ("p", "x"): "hexadecimal dump",
    ("pd", "f"): "disassemble function",
    ("pd", "j"): "JSON disassembly",
    ("px", "w"): "32-bit word hexdump",
    ("s", "+"): "seek forward",
    ("s", "-"): "seek backward",
    ("s", "e"): "seek end",
    ("s", "r"): "seek relative",
    ("t", "s"): "structs",
    ("t", "t"): "typedefs",
    ("t", "u"): "unions",
    ("w", "a"): "write assembled opcode",
    ("w", "c"): "write cache",
    ("w", "f"): "write file contents",
    ("w", "o"): "write with operation",
    ("w", "v"): "write numeric value",
    ("w", "x"): "write hexpairs",
    ("y", "y"): "paste yanked data",
    ("z", "a"): "add zignature",
    ("z", "f"): "FLIRT signatures",
    ("z", "s"): "zignature spaces",
}

COMMAND_SUFFIX_MEANINGS = {
    "?": "show help for the current command family",
    "*": "emit r2 script commands",
    "j": "emit JSON output when supported",
    "q": "quiet or compact output",
    "v": "verbose or value-oriented output",
    "l": "list",
    "-": "delete, remove, or move backward depending on family",
    "+": "add, append, or move forward depending on family",
    ".": "operate at the current offset or current object",
}

COMMAND_SYSTEM_PROMPT = (
    "You are a radare2 command trainer. Explain command construction, "
    "subcommand letters, prefixes, suffixes, modifiers, and executable examples."
)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_command_token(raw: str) -> str:
    token = raw.strip().strip("`'\"")
    if not token:
        return ""
    if token.startswith("%["):
        return "%"
    if token.startswith("(foo") or token.startswith("("):
        return "("
    if token.startswith("[.:"):
        return "commandline"
    if token.startswith("@@@"):
        return "@@@"
    if token.startswith("@@"):
        return "@@"
    if token.startswith("--"):
        return "--"
    token = token.replace("\\n", "")
    token = re.sub(r"\[.*", "", token)
    token = re.sub(r"<.*", "", token)
    token = re.sub(r"\(.*", "", token) if not token.startswith("(") else token
    token = token.strip()
    if not token:
        return ""
    token = token.split()[0].strip(" ,;:")
    if token.startswith("|"):
        token = token[1:].strip()
    if token in {"Usage", "Usage:", "Examples", "Environment"}:
        return ""
    return token[:48]


def command_token_is_useful(token: str) -> bool:
    if not token or token in {"-", "--"}:
        return bool(token == "--")
    if len(token) > 48:
        return False
    if re.match(r"^[A-Za-z0-9_]+:", token):
        return False
    return any(ch.isalnum() or ch in "?!%#$().:=/@+-*" for ch in token)


def command_line_summary(line: str, token: str) -> str:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:].strip()
    if body.startswith("Usage:"):
        body = body.removeprefix("Usage:").strip()
    parts = re.split(r"\s{2,}", body, maxsplit=1)
    if len(parts) == 2:
        return parts[1].strip()
    body = body.removeprefix(token).strip(" -#")
    return body.strip()


def command_candidates_from_block(usage_line: str, block: list[str], source_ref: str, max_variants: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    usage_body = usage_line.removeprefix("Usage:").strip()
    usage_token = normalize_command_token(usage_body)
    subject_id, subject, question = command_grammar_subject(usage_line)
    if command_token_is_useful(usage_token):
        syntax = re.split(r"\s{2,}", usage_body, maxsplit=1)[0].strip() or usage_token
        candidates.append({
            "command": usage_token,
            "syntax": syntax,
            "summary": command_line_summary(usage_line, usage_token) or subject,
            "question": f"How does the radare2 command `{usage_token}` work and how is it constructed?",
            "line": usage_line,
            "source_ref": source_ref,
        })
    in_non_command_section = False
    for line in block[1:]:
        stripped = line.strip()
        if not stripped:
            continue
        section_name = stripped.lstrip("| ").rstrip(":")
        if section_name in {"Environment", "Examples", "Argument support", "modifier", "endmodifier", "column"}:
            in_non_command_section = True
            continue
        if not stripped.startswith("|") or in_non_command_section:
            continue
        body = stripped[1:].strip()
        if not body or body.startswith(("#", "NOTE:", "WIP:")):
            continue
        raw_token = body.split()[0]
        command = normalize_command_token(raw_token)
        if not command_token_is_useful(command):
            continue
        candidates.append({
            "command": command,
            "syntax": raw_token,
            "summary": command_line_summary(stripped, raw_token),
            "question": f"How does the radare2 command `{command}` work and how is it constructed?",
            "line": stripped,
            "source_ref": source_ref,
        })
        if len(candidates) >= max_variants + 1:
            break
    return candidates


def command_decomposition(command: str) -> tuple[list[dict[str, Any]], list[str]]:
    if command == "commandline":
        return ([{"part": "commandline", "meaning": "full command-line composition syntax", "known": True}], [])
    if command in {"@@", "@@@"}:
        meaning = "iterator over offsets" if command == "@@" else "iterator over offset and size pairs"
        return ([{"part": command, "meaning": meaning, "known": True}], [])
    if command in COMMAND_ROOT_MEANINGS:
        return ([{"part": command, "meaning": COMMAND_ROOT_MEANINGS[command], "known": True}], [])
    parts: list[dict[str, Any]] = []
    unknown: list[str] = []
    prefix = ""
    for index, ch in enumerate(command):
        if ch.isspace():
            break
        if ch in "[]<>,;`'\"":
            continue
        meaning = COMMAND_CONTEXT_LETTER_MEANINGS.get((prefix, ch))
        if meaning is None and index == 0:
            meaning = COMMAND_ROOT_MEANINGS.get(ch)
        if meaning is None:
            meaning = COMMAND_SUFFIX_MEANINGS.get(ch)
        known = meaning is not None
        if meaning is None:
            meaning = "unknown in this local command model"
            unknown.append(ch)
        parts.append({"part": ch, "prefix": prefix + ch, "meaning": meaning, "known": known})
        prefix += ch
    return parts, unknown


def command_decomposition_text(command: str, parts: list[dict[str, Any]]) -> str:
    if not parts:
        return "No command-letter decomposition was inferred."
    rendered = []
    for part in parts:
        name = str(part.get("part", ""))
        meaning = str(part.get("meaning", ""))
        prefix = str(part.get("prefix", name))
        if prefix and prefix != name and len(name) == 1:
            rendered.append(f"`{name}` under `{prefix[:-1]}` means {meaning}")
        else:
            rendered.append(f"`{name}` means {meaning}")
    return "; ".join(rendered) + "."


def command_row_from_candidate(candidate: dict[str, Any], verification: Verification, r2_source: Path, r2_bin: Path) -> dict[str, Any]:
    command = str(candidate["command"])
    parts, unknown = command_decomposition(command)
    summary = str(candidate.get("summary") or "").strip()
    syntax = str(candidate.get("syntax") or command).strip()
    line = str(candidate.get("line") or "").strip()
    source_ref = str(candidate.get("source_ref") or "r2:?*")
    status = "needs-memory" if unknown or len(summary) < 8 else "documented"
    decomposition = command_decomposition_text(command, parts)
    if command == "afl":
        summary = summary or "list all analyzed functions"
    answer_parts = [
        f"`{command}` is documented by radare2 syntax `{syntax}`.",
        f"Command construction: {decomposition}",
    ]
    if summary:
        answer_parts.append(f"Documented behavior: {summary}.")
    if status == "needs-memory":
        answer_parts.append("This row is marked `needs-memory` because the local model could not confidently explain every letter or the help text is too thin; ask a human to refine it with `make memory`.")
    answer_parts.append(f"Evidence line from `{source_ref}`:\n{line}")
    question = str(candidate.get("question") or f"How does the radare2 command `{command}` work?")
    fingerprint = stable_hash(command, syntax, summary, decomposition, line)
    row_id = "agentic.command." + safe_id_part(command) + "." + stable_hash(source_ref, command, length=8)
    checks = [{"type": "contains", "value": line[:120]}] if line else [{"type": "nonempty"}]
    ok, checked, _reason = evaluate_checks(verification.output, checks)
    if not ok:
        checked = verification.checks
    return {
        "command": command,
        "content_fingerprint": fingerprint,
        "decomposition": parts,
        "id": row_id,
        "kind": "agentic_command",
        "messages": [
            {"role": "system", "content": COMMAND_SYSTEM_PROMPT},
            {"role": "user", "content": question},
            {"role": "assistant", "content": "\n\n".join(answer_parts)},
        ],
        "source_refs": [source_ref],
        "status": status,
        "syntax": syntax,
        "tags": ["agentic-command", "radare2-command", "command-grammar", status],
        "topic": "command." + safe_id_part(command),
        "unknown_parts": unknown,
        "verification": {
            "status": verification.status,
            "returncode": verification.returncode,
            "command_line": sanitize_command_line(verification.command_line, r2_source, r2_bin),
            "checks": checked,
            "output_excerpt": output_excerpt(sanitize_text("\n".join([line] if line else verification.output.splitlines()[:6]), r2_source), 1200),
        },
    }


def merge_command_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_command: dict[str, dict[str, Any]] = {}
    for row in rows:
        command = str(row.get("command", ""))
        if not command:
            continue
        old = by_command.get(command)
        if old is None:
            by_command[command] = row
            continue
        old_score = (0 if old.get("status") == "documented" else -2) + len(row_message_content(old, "assistant")) // 200
        new_score = (0 if row.get("status") == "documented" else -2) + len(row_message_content(row, "assistant")) // 200
        if new_score >= old_score:
            refs = list(dict.fromkeys(list(old.get("source_refs", [])) + list(row.get("source_refs", []))))
            row["source_refs"] = refs
            by_command[command] = row
    return sorted(by_command.values(), key=lambda item: safe_id_part(str(item.get("command", ""))))


def command_training_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        out.append({
            "content_fingerprint": row.get("content_fingerprint", ""),
            "id": row.get("id", ""),
            "kind": "agentic_command",
            "messages": row.get("messages", []),
            "source_refs": row.get("source_refs", []),
            "tags": row.get("tags", []),
            "topic": row.get("topic", ""),
            "verification": row.get("verification", {}),
        })
    return out



GENERIC_COMMAND_MEMORY_TAGS = {
    "radare2",
    "command",
    "commands",
    "command-grammar",
    "agentic-commands",
    "training-data",
    "memory",
    "shell",
    "analysis",
    "command-composition",
    "esil",
    "exit",
    "function-list",
    "io",
    "move",
    "projects",
    "quit",
    "repeat-prefix",
    "restore",
    "save",
    "seek",
}


def command_lookup_maps(rows: list[dict[str, Any]]) -> tuple[set[str], dict[str, str]]:
    commands = {str(row.get("command", "")) for row in rows if row.get("command")}
    lower: dict[str, str] = {}
    for command in commands:
        lower.setdefault(command.lower(), command)
    return commands, lower


def memory_row_text(row: dict[str, Any]) -> str:
    parts = [
        str(row.get("topic", "")),
        str(row.get("question", "")),
        str(row.get("highlight", "")),
        str(row.get("details", "")),
    ]
    parts.extend(str(tag) for tag in row.get("tags", []) if str(tag).strip())
    return "\n".join(part for part in parts if part.strip())


def candidate_memory_commands(row: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    topic_question = "\n".join(str(row.get(key, "")) for key in ("topic", "question"))
    full_text = memory_row_text(row)
    for match in re.finditer(r"radare2 command [`'\"]([^`'\"]{1,48})[`'\"]", topic_question, re.IGNORECASE):
        candidates.append(match.group(1))
    for tag in row.get("tags", []):
        tag_value = str(tag).strip()
        if tag_value and tag_value.lower() not in GENERIC_COMMAND_MEMORY_TAGS:
            candidates.append(tag_value)
    for match in re.finditer(r"`([^`]{1,48})`", topic_question):
        candidates.append(match.group(1))
    for match in re.finditer(r"(?<![A-Za-z0-9_])\d+[A-Za-z][A-Za-z0-9_?!+*.-]{1,24}(?![A-Za-z0-9_])", full_text):
        candidates.append(match.group(0))
    return list(dict.fromkeys(candidates))


def match_memory_command(raw: str, command_set: set[str], lower_lookup: dict[str, str]) -> list[str]:
    token = normalize_command_token(raw)
    if not token:
        return []
    if token in command_set:
        return [token]
    if len(token) == 1 and token.isupper():
        return []
    if token.lower() in lower_lookup:
        return [lower_lookup[token.lower()]]
    if token.startswith("0x") and "0xaddr" in command_set:
        return ["0xaddr"]
    if token.startswith("-") and token[:2] in command_set:
        return [token[:2]]
    return []


def accepted_command_memories(rows: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    command_set, lower_lookup = command_lookup_maps(rows)
    by_command: dict[str, list[dict[str, Any]]] = {}
    unmatched: list[dict[str, Any]] = []
    for memory in read_jsonl(MEMORY_PATH):
        if memory.get("status") != "accepted":
            continue
        text = memory_row_text(memory).lower()
        if "radare2" not in text:
            continue
        matches: list[str] = []
        for candidate in candidate_memory_commands(memory):
            matches.extend(match_memory_command(candidate, command_set, lower_lookup))
        matches = list(dict.fromkeys(matches))
        if not matches:
            unmatched.append(memory)
            continue
        for command in matches:
            by_command.setdefault(command, []).append(memory)
    return by_command, unmatched


def memory_to_command_guess(memory: dict[str, Any]) -> str:
    for candidate in candidate_memory_commands(memory):
        token = normalize_command_token(candidate)
        if token and token.lower() not in GENERIC_COMMAND_MEMORY_TAGS:
            return token
    return ""


def command_memory_answer_section(memories: list[dict[str, Any]]) -> str:
    sections = []
    for memory in memories:
        highlight = str(memory.get("highlight", "")).strip()
        details = str(memory.get("details", "")).strip()
        memory_id = str(memory.get("id", "")).strip()
        body = []
        if highlight:
            body.append(highlight)
        if details:
            body.append("Details:\n" + details)
        if memory_id:
            body.append(f"Memory id: {memory_id}")
        if body:
            sections.append("\n".join(body))
    if not sections:
        return ""
    return "Human memory:\n" + "\n\n".join(sections)


def strip_needs_memory_notice(answer: str) -> str:
    notice = "This row is marked `needs-memory` because the local model could not confidently explain every letter or the help text is too thin; ask a human to refine it with `make memory`."
    return answer.replace("\n\n" + notice, "").replace(notice + "\n\n", "").replace(notice, "").strip()


def apply_command_memories(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
    by_command, unmatched = accepted_command_memories(rows)
    output: list[dict[str, Any]] = []
    applied = 0
    for row in rows:
        command = str(row.get("command", ""))
        memories = by_command.get(command, [])
        if not memories:
            output.append(row)
            continue
        updated = copy.deepcopy(row)
        answer = strip_needs_memory_notice(row_message_content(updated, "assistant"))
        memory_section = command_memory_answer_section(memories)
        if memory_section and memory_section not in answer:
            answer = answer.rstrip() + "\n\n" + memory_section
        for message in updated.get("messages", []):
            if isinstance(message, dict) and message.get("role") == "assistant":
                message["content"] = answer
        previous_unknown = list(updated.get("unknown_parts", []))
        updated["memory_refs"] = [str(memory.get("id")) for memory in memories if memory.get("id")]
        updated["memory_resolved_parts"] = previous_unknown
        updated["unknown_parts"] = []
        updated["status"] = "human-reviewed"
        tags = [str(tag) for tag in updated.get("tags", []) if str(tag) not in {"needs-memory", "documented", "human-reviewed"}]
        updated["tags"] = list(dict.fromkeys([*tags, "human-reviewed", "human-memory"]))
        refs = list(updated.get("source_refs", []))
        refs.append("data/memory/memory.jsonl")
        updated["source_refs"] = list(dict.fromkeys(refs))
        updated["content_fingerprint"] = stable_hash(row.get("content_fingerprint", ""), *(memory.get("content_fingerprint", memory.get("id", "")) for memory in memories))
        output.append(updated)
        applied += len(memories)

    command_set = {str(row.get("command", "")) for row in output if row.get("command")}
    synthetic = 0
    for memory in unmatched:
        command = memory_to_command_guess(memory)
        if not command or command in command_set:
            continue
        parts, _unknown = command_decomposition(command)
        section = command_memory_answer_section([memory])
        row_id = "agentic.command.memory." + safe_id_part(command) + "." + stable_hash(memory.get("id", command), length=8)
        output.append({
            "command": command,
            "content_fingerprint": stable_hash(command, memory.get("content_fingerprint", memory.get("id", ""))),
            "decomposition": parts,
            "id": row_id,
            "kind": "agentic_command",
            "memory_refs": [str(memory.get("id"))] if memory.get("id") else [],
            "messages": [
                {"role": "system", "content": COMMAND_SYSTEM_PROMPT},
                {"role": "user", "content": f"How does the radare2 command `{command}` work and how is it constructed?"},
                {"role": "assistant", "content": section or str(memory.get("highlight", ""))},
            ],
            "source_refs": ["data/memory/memory.jsonl"],
            "status": "human-reviewed",
            "syntax": command,
            "tags": ["agentic-command", "radare2-command", "command-grammar", "human-reviewed", "human-memory"],
            "topic": "command." + safe_id_part(command),
            "unknown_parts": [],
        })
        command_set.add(command)
        synthetic += 1
    return sorted(output, key=lambda item: safe_id_part(str(item.get("command", "")))), applied, synthetic


def command_memory_topic(row: dict[str, Any]) -> dict[str, Any]:
    command = str(row.get("command", ""))
    unknown = ", ".join(map(str, row.get("unknown_parts", []))) or "thin help text"
    topic = f"radare2 command `{command}` decomposition"
    question = (
        f"Please clarify the radare2 command `{command}`: explain what each letter, suffix, or modifier means, "
        f"how it composes with parent command families, and give one precise usage example. Current gap: {unknown}."
    )
    return {
        "created_at": utc_timestamp(),
        "id": "topic." + stable_hash(topic, question),
        "question": question,
        "source": {"channel": "agentic-commands"},
        "status": "pending",
        "tags": ["radare2", "command-grammar", "agentic-commands", safe_id_part(command)],
        "topic": topic,
    }


def existing_memory_topics_and_facts() -> set[str]:
    seen: set[str] = set()
    for path in (MEMORY_TOPICS_PATH, MEMORY_PATH):
        for row in read_jsonl(path):
            if row.get("id"):
                seen.add(str(row.get("id")))
            topic = str(row.get("topic", ""))
            if topic:
                seen.add(topic)
    return seen


def queue_command_memory_topics(
    topics: list[dict[str, Any]],
    queue_memory: bool,
    output_path: Path = COMMANDS_MEMORY_TOPICS_PATH,
) -> tuple[int, int]:
    write_jsonl(output_path, topics)
    if not queue_memory:
        return len(topics), 0
    existing_rows = read_jsonl(MEMORY_TOPICS_PATH)
    seen_ids = {str(row.get("id")) for row in existing_rows if row.get("id")}
    seen_topics = {str(row.get("topic")) for row in existing_rows if row.get("topic")}
    queued = []
    for topic in topics:
        topic_id = str(topic.get("id", ""))
        topic_name = str(topic.get("topic", ""))
        if topic_id and topic_id not in seen_ids and topic_name not in seen_topics:
            queued.append(topic)
            seen_ids.add(topic_id)
            seen_topics.add(topic_name)
    if queued:
        write_jsonl_if_changed(MEMORY_TOPICS_PATH, existing_rows + queued)
    return len(topics), len(queued)


COMMAND_EXPRESSION_DENY_WORDS = {
    "",
    "--",
    "-",
    "main",
    "entry0",
    "hello",
    "phase",
    "write",
    "true",
    "false",
    "null",
}

COMMAND_EXPRESSION_DENY_PREFIXES = (
    "./",
    "../",
    "/",
    "http://",
    "https://",
    "malloc://",
    "hex://",
    "test/",
    "libr/",
    "bin/",
    "scripts/",
    "str.",
    "sym.",
    "fcn.",
    "loc.",
    "section.",
    "reloc.",
    "radare2 ",
    "r2 ",
    "rabin2 ",
    "rasm2 ",
)

COMMON_R2_COMMAND_RE = re.compile(
    r"^(?:"
    r"a{1,5}|a[efxobrst][A-Za-z0-9_.+*?=-]*|"
    r"p(?:$|[dx8ifcjsoD][A-Za-z0-9_.+*?=-]*)|"
    r"i(?:$|[IizESVROAjq*?+\-][A-Za-z0-9_.+*?=-]*)|"
    r"d(?:$|[bcmsr][A-Za-z0-9_.+*?=-]*)|"
    r"e|s[+-]*|w[A-Za-z0-9_.+*?=-]*|"
    r"o[A-Za-z0-9_.+*?=-]*|m|md|L[A-Za-z0-9_.+*?=-]*|"
    r"\?.+|[+-]\d+"
    r")$"
)


def clean_knowledge_command_expression(raw: str) -> str:
    expr = raw.strip().strip("`'\"")
    expr = expr.replace("\\n", " ").replace("\n", " ")
    expr = re.sub(r"\s+", " ", expr).strip()
    if expr.endswith(".") and not expr.startswith("."):
        expr = expr[:-1].rstrip()
    return expr[:160]


def command_expression_base(expression: str) -> str:
    expr = expression.strip()
    if not expr:
        return ""
    if expr.startswith("("):
        return "("
    if expr.startswith("js:"):
        return "js:"
    token = re.split(r"\s+", expr, maxsplit=1)[0]
    token = re.split(r"[@~|><;]", token, maxsplit=1)[0]
    if re.match(r"^[+-]\d+$", token):
        return token[:2]
    if re.match(r"^\d+[A-Za-z]", token):
        token = re.sub(r"^\d+", "", token)
    return normalize_command_token(token)


def command_expression_is_composed(expression: str) -> bool:
    expr = expression.strip()
    base = command_expression_base(expr)
    if not expr or not base:
        return False
    if re.match(r"^\d+[A-Za-z]", expr):
        return True
    if expr != base and (" " in expr or any(mark in expr for mark in ("@", "~", "@@", ";", "|", ">", "<", "`", "$"))):
        return True
    return False


def is_probable_r2_command_expression(expression: str, command_names: set[str]) -> bool:
    expr = expression.strip()
    if not expr or len(expr) > 160:
        return False
    lower = expr.lower()
    if lower in COMMAND_EXPRESSION_DENY_WORDS:
        return False
    if lower.startswith(COMMAND_EXPRESSION_DENY_PREFIXES):
        return False
    if re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+|[A-Za-z0-9_.-]+\.(?:c|h|md|json|txt|bin|exe|img|o|so|dylib))", expr):
        return False
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://.*", expr):
        return False
    base = command_expression_base(expr)
    if not base or base.lower() in COMMAND_EXPRESSION_DENY_WORDS:
        return False
    if expr in command_names or base in command_names:
        return True
    if expr.startswith("js:"):
        return True
    if base in COMMAND_ROOT_MEANINGS:
        return True
    if base and base[0] in COMMAND_ROOT_MEANINGS and command_expression_is_composed(expr):
        return True
    return bool(COMMON_R2_COMMAND_RE.match(base))


def knowledge_command_expressions_from_row(row: dict[str, Any]) -> list[str]:
    expressions: list[str] = []
    verification = row.get("verification")
    if isinstance(verification, dict):
        command_line = verification.get("command_line")
        if isinstance(command_line, list):
            for idx, arg in enumerate(command_line[:-1]):
                if arg == "-c":
                    expressions.append(str(command_line[idx + 1]))
    text = "\n".join(
        part for part in (
            row_message_content(row, "user"),
            row_message_content(row, "assistant"),
        )
        if part
    )
    for line in text.splitlines():
        match = re.match(r"^\s*-\s+`([^`]{1,160})`\s*$", line)
        if match:
            expressions.append(match.group(1))
    for match in re.finditer(r"`([^`\n]{1,160})`", text):
        expressions.append(match.group(1))
    return list(dict.fromkeys(clean_knowledge_command_expression(expr) for expr in expressions if clean_knowledge_command_expression(expr)))


def knowledge_command_usage_items(command_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    command_names = {str(row.get("command")) for row in command_rows if row.get("command")}
    by_expression: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(KNOWLEDGE_PATH):
        row_id = str(row.get("id", ""))
        if not row_id:
            continue
        row_topic = str(row.get("topic", ""))
        row_refs = [str(ref) for ref in row.get("source_refs", []) if str(ref).strip()]
        seen_in_row: set[str] = set()
        for expression in knowledge_command_expressions_from_row(row):
            if expression in seen_in_row or not is_probable_r2_command_expression(expression, command_names):
                continue
            seen_in_row.add(expression)
            item = by_expression.setdefault(expression, {
                "expression": expression,
                "base": command_expression_base(expression),
                "count": 0,
                "knowledge_ids": [],
                "knowledge_topics": [],
                "source_refs": [],
            })
            item["count"] += 1
            if row_id not in item["knowledge_ids"]:
                item["knowledge_ids"].append(row_id)
            if row_topic and row_topic not in item["knowledge_topics"]:
                item["knowledge_topics"].append(row_topic)
            for ref in row_refs:
                if ref not in item["source_refs"]:
                    item["source_refs"].append(ref)
    return list(by_expression.values())


def command_row_for_expression(expression: str, command_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    command_set, lower_lookup = command_lookup_maps(command_rows)
    candidates = [expression, command_expression_base(expression)]
    for candidate in candidates:
        for command in match_memory_command(candidate, command_set, lower_lookup):
            for row in command_rows:
                if row.get("command") == command:
                    return row
    return None


def should_ask_knowledge_command_question(item: dict[str, Any], command_row: dict[str, Any] | None) -> bool:
    expression = str(item.get("expression", ""))
    if not expression:
        return False
    status = str(command_row.get("status")) if command_row else "missing-command-row"
    if status in {"needs-memory", "missing-command-row"}:
        return True
    return command_expression_is_composed(expression)


def knowledge_command_memory_topic(item: dict[str, Any], command_row: dict[str, Any] | None) -> dict[str, Any]:
    expression = str(item.get("expression", ""))
    base = str(item.get("base", "")) or expression
    status = str(command_row.get("status")) if command_row else "missing-command-row"
    unknown = ", ".join(map(str, command_row.get("unknown_parts", []))) if command_row else "not present in command database"
    if not unknown:
        unknown = "real workflow composition"
    knowledge_ids = [str(value) for value in item.get("knowledge_ids", [])][:4]
    source_refs = [str(value) for value in item.get("source_refs", [])][:4]
    topic = f"radare2 knowledge command `{expression}` workflow usage"
    question = (
        f"The existing agentic knowledge database uses `{expression}` in verified workflow rows "
        f"{', '.join(knowledge_ids) or 'unknown'}. Please explain how this radare2 command expression is constructed: "
        f"base command `{base}`, command letters/subcommands, arguments, repeat prefixes, output suffixes, "
        f"and modifiers such as `@`, `~`, `@@`, pipes, or redirection. Also explain why it is used in that workflow. "
        f"Current command database status: {status}; gap: {unknown}."
    )
    return {
        "created_at": utc_timestamp(),
        "id": "topic." + stable_hash(topic, question),
        "question": question,
        "source": {
            "channel": "agentic-knowledge",
            "knowledge_ids": knowledge_ids,
            "source_refs": source_refs,
        },
        "status": "pending",
        "tags": ["radare2", "command-grammar", "agentic-commands", "knowledge-db", safe_id_part(base)],
        "topic": topic,
    }


def knowledge_command_memory_topics(limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    command_rows = read_jsonl(COMMANDS_DB_PATH)
    existing = existing_memory_topics_and_facts()
    topics: list[dict[str, Any]] = []
    ranked: list[tuple[tuple[int, int, int, str], dict[str, Any], dict[str, Any] | None]] = []
    for item in knowledge_command_usage_items(command_rows):
        command_row = command_row_for_expression(str(item.get("expression", "")), command_rows)
        if not should_ask_knowledge_command_question(item, command_row):
            continue
        status = str(command_row.get("status")) if command_row else "missing-command-row"
        weak_rank = 0 if status in {"needs-memory", "missing-command-row"} else 1
        composed_rank = 0 if command_expression_is_composed(str(item.get("expression", ""))) else 1
        ranked.append((
            (weak_rank, composed_rank, -int(item.get("count", 0)), safe_id_part(str(item.get("expression", "")))),
            item,
            command_row,
        ))
    max_per_base = max(1, int(os.environ.get("AGENTIC_KNOWLEDGE_COMMAND_MAX_PER_BASE", "3")))
    per_base: dict[str, int] = {}
    for _rank, item, command_row in sorted(ranked, key=lambda value: value[0]):
        if len(topics) >= limit:
            break
        base = str(item.get("base", ""))
        if per_base.get(base, 0) >= max_per_base:
            continue
        topic = knowledge_command_memory_topic(item, command_row)
        if topic["id"] in existing or topic["topic"] in existing:
            continue
        topics.append(topic)
        per_base[base] = per_base.get(base, 0) + 1
        existing.add(topic["id"])
        existing.add(topic["topic"])
    return topics



def heuristic_command_memory_topics(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    existing = existing_memory_topics_and_facts()
    topics: list[dict[str, Any]] = []
    priority = sorted(rows, key=lambda row: (row.get("status") != "needs-memory", len(str(row.get("command", "")))))
    for row in priority:
        if len(topics) >= limit:
            break
        if row.get("status") != "needs-memory":
            continue
        topic = command_memory_topic(row)
        if topic["id"] in existing or topic["topic"] in existing:
            continue
        topics.append(topic)
        existing.add(topic["id"])
        existing.add(topic["topic"])
    return topics


def ai_command_memory_topics(gaps: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    mode = args.ai
    if mode == "off" or not gaps:
        return []
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        if mode == "required":
            raise SystemExit("OPENAI_API_KEY is required for --ai required")
        return []
    try:
        import openai  # type: ignore
    except ImportError as exc:
        if mode == "required":
            raise SystemExit("The openai package is required for --ai required") from exc
        return []
    sample = [
        {
            "command": row.get("command"),
            "syntax": row.get("syntax"),
            "unknown_parts": row.get("unknown_parts", []),
            "answer": row_message_content(row, "assistant")[:800],
        }
        for row in gaps[: args.memory_limit]
    ]
    prompt = (
        "You are improving a radare2 command-learning memory queue. "
        "Given command rows with weak decomposition, return JSON list items with topic, question, and tags. "
        "Ask questions a human can answer to explain each command letter, suffix, modifier, and one usage example.\n\n"
        + json.dumps(sample, ensure_ascii=False, indent=2)
    )
    client = openai.OpenAI(base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    response = client.chat.completions.create(
        model=args.model,
        messages=[{"role": "user", "content": prompt}],
        temperature=args.temperature,
        top_p=0.9,
        max_tokens=4000,
    )
    raw = (response.choices[0].message.content or "[]").replace("```json", "").replace("```", "").strip()
    proposals_path = COMMANDS_DIR / "ai-memory-topics-raw.txt"
    proposals_path.write_text(raw, encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        if mode == "required":
            raise SystemExit(f"model did not return JSON; raw output saved to {repo_path_ref(proposals_path)}")
        return []
    topics: list[dict[str, Any]] = []
    if not isinstance(parsed, list):
        return topics
    for item in parsed:
        if not isinstance(item, dict):
            continue
        topic = str(item.get("topic", "")).strip()
        question = str(item.get("question", "")).strip()
        if not topic or not question:
            continue
        tags = item.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        tag_values = [str(tag) for tag in tags if str(tag).strip()]
        topics.append({
            "created_at": utc_timestamp(),
            "id": "topic." + stable_hash(topic, question),
            "question": question,
            "source": {"channel": "agentic-commands-ai"},
            "status": "pending",
            "tags": list(dict.fromkeys(["radare2", "command-grammar", "agentic-commands", *tag_values])),
            "topic": topic,
        })
        if len(topics) >= args.memory_limit:
            break
    return topics


def build_agentic_command_database(args: argparse.Namespace) -> int:
    r2_bin = pick_r2_bin(args.r2_bin)
    r2_source = Path(args.r2_source)
    rows: list[dict[str, Any]] = []
    help_topics = list(dict.fromkeys((topic, command, title, tuple(refs)) for topic, command, title, refs in GROWTH_HELP_TOPICS))
    variants_per_block = max(1, args.variants_per_block)
    for _topic, command, _title, refs_tuple in help_topics:
        entry = {"id": f"agentic.commands.help.{safe_id_part(command)}", "kind": "r2cmd", "answer": command, "fixture": "--", "checks": [{"type": "nonempty"}]}
        verification = run_entry(entry, r2_bin, r2_source, args.timeout)
        if not verification.ok:
            continue
        source_ref = f"r2:{command}"
        refs = [source_ref, *list(refs_tuple)]
        for usage_line, block in parse_command_grammar_blocks(verification.output, r2_source):
            for candidate in command_candidates_from_block(usage_line, block, source_ref, variants_per_block):
                row = command_row_from_candidate(candidate, verification, r2_source, r2_bin)
                row["source_refs"] = list(dict.fromkeys(refs + row.get("source_refs", [])))
                rows.append(row)
    full_entry = {
        "id": "agentic.commands.full_help",
        "kind": "reasoning_task",
        "fixture": "--",
        "starter_commands": ["?*"],
        "checks": [{"type": "contains", "value": "Append '?' to any char command"}],
        "answer": "",
        "question": "",
    }
    verification = run_entry(full_entry, r2_bin, r2_source, args.timeout)
    if verification.ok:
        for usage_line, block in parse_command_grammar_blocks(verification.output, r2_source):
            for candidate in command_candidates_from_block(usage_line, block, "r2:?*", variants_per_block):
                rows.append(command_row_from_candidate(candidate, verification, r2_source, r2_bin))
    rows = merge_command_rows(rows)
    rows, memory_applied, synthetic_memory_rows = apply_command_memories(rows)
    if args.limit > 0 and len(rows) > args.limit:
        human_rows = [row for row in rows if row.get("status") == "human-reviewed"]
        other_rows = [row for row in rows if row.get("status") != "human-reviewed"]
        rows = sorted(
            human_rows + other_rows[: max(0, args.limit - len(human_rows))],
            key=lambda item: safe_id_part(str(item.get("command", ""))),
        )
    previous = read_jsonl(COMMANDS_DB_PATH)
    previous_by_id = rows_by_id(previous)
    changed = [row for row in rows if previous_by_id.get(str(row.get("id"))) != row]
    write_jsonl(COMMANDS_DB_PATH, rows)
    write_jsonl(COMMANDS_TRAINING_PATH, command_training_rows(rows))
    gaps = [row for row in rows if row.get("status") == "needs-memory"]
    topics: list[dict[str, Any]] = []
    knowledge_topics: list[dict[str, Any]] = []
    if args.memory_limit > 0:
        knowledge_reserve = max(1, args.memory_limit // 3) if args.memory_limit > 1 else 0
        gap_topic_limit = max(0, args.memory_limit - knowledge_reserve)
        topics = ai_command_memory_topics(gaps, args)[:gap_topic_limit]
        if len(topics) < gap_topic_limit:
            topics.extend(heuristic_command_memory_topics(gaps, gap_topic_limit - len(topics)))
        if len(topics) < args.memory_limit:
            knowledge_topics = knowledge_command_memory_topics(args.memory_limit - len(topics))
            topics.extend(knowledge_topics)
        if len(topics) < args.memory_limit:
            topics.extend(heuristic_command_memory_topics(gaps, args.memory_limit - len(topics)))
    topics = topics[: args.memory_limit]
    topic_count, queued_count = queue_command_memory_topics(topics, args.queue_memory)
    index = {
        "command_rows": len(rows),
        "documented_rows": len([row for row in rows if row.get("status") == "documented"]),
        "human_reviewed_rows": len([row for row in rows if row.get("status") == "human-reviewed"]),
        "needs_memory_rows": len(gaps),
        "last_changed_rows": len(changed),
        "memory_rows_applied": memory_applied,
        "synthetic_memory_rows": synthetic_memory_rows,
        "memory_topics": topic_count,
        "knowledge_memory_topics": len(knowledge_topics),
        "memory_topics_queued": queued_count,
        "source_refs": ["r2:?*", "r2:<command>? help"],
        "ai_mode": args.ai,
        "updated_at": utc_timestamp(),
    }
    COMMANDS_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    COMMANDS_INDEX_PATH.write_text(json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"agentic commands {len(rows)} rows, {len(changed)} changed, {len(gaps)} need memory")
    print(f"agentic commands memory applied {memory_applied} accepted memories, {synthetic_memory_rows} synthetic rows")
    print(f"agentic commands db {repo_path_ref(COMMANDS_DB_PATH)}")
    print(f"agentic commands training {repo_path_ref(COMMANDS_TRAINING_PATH)}")
    print(f"agentic commands memory topics {topic_count} written to {repo_path_ref(COMMANDS_MEMORY_TOPICS_PATH)}")
    if knowledge_topics:
        print(f"agentic commands knowledge memory topics {len(knowledge_topics)} mined from {repo_path_ref(KNOWLEDGE_PATH)}")
    if args.queue_memory:
        print(f"agentic commands queued {queued_count} topics for make memory in {repo_path_ref(MEMORY_TOPICS_PATH)}")
    for row in rows[: min(8, len(rows))]:
        print(f"  command {row.get('command')}: {row.get('status')} - {row_message_content(row, 'user')}")
    return 0


def build_help_frontier(r2_bin: Path, r2_source: Path, timeout: int, seen: set[str], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for topic, command, title, refs in GROWTH_HELP_TOPICS:
        if len(rows) >= limit:
            break
        row_id = f"knowledge.{topic}"
        if row_id in seen:
            continue
        entry = {
            "id": row_id,
            "kind": "r2cmd",
            "answer": command,
            "fixture": "--",
            "checks": [{"type": "nonempty"}],
        }
        verification = run_entry(entry, r2_bin, r2_source, timeout)
        if verification.ok:
            answer = compact_text(verification.output, r2_source, 1800)
            rows.append(knowledge_row(
                row_id,
                topic,
                f"What does radare2 document for `{command}`?",
                answer,
                refs,
                r2_source,
                tags=["help", "r2cmd", command.rstrip("?")],
                verification=verification_summary(verification, r2_source, r2_bin),
                title=title,
            ))
            seen.add(row_id)
        else:
            pending.append(growth_pending(row_id, "help", command, verification, r2_source, refs))
            seen.add(row_id)
    return rows, pending


def extract_markdown_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        m = re.match(r"^#\s+(.+)", line.strip())
        if m:
            return m.group(1).strip()
    return fallback


def iter_source_docs(r2_source: Path) -> list[Path]:
    paths: set[Path] = set()
    for pattern in GROWTH_DOC_GLOBS:
        paths.update(path for path in r2_source.glob(pattern) if path.is_file())
    return sorted(paths)


def iter_local_book_docs(r2_source: Path) -> list[Path]:
    candidates = []
    env = os.environ.get("R2_BOOK_SOURCE")
    if env:
        candidates.append(Path(env))
    candidates.extend([ROOT.parent / "radare2-book", r2_source.parent / "radare2-book"])
    paths: set[Path] = set()
    for base in candidates:
        if base.is_dir():
            paths.update(path for path in base.rglob("*.md") if path.is_file())
    return sorted(paths)


def build_doc_knowledge(paths: list[Path], base: Path, source_prefix: str, r2_source: Path, seen: set[str], limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        if len(rows) >= limit:
            break
        try:
            if path.stat().st_size > 250_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(raw.strip()) < 120:
            continue
        try:
            ref = path.resolve().relative_to(base.resolve()).as_posix()
        except (OSError, ValueError):
            ref = path.name
        source_ref = f"{source_prefix}:{ref}" if source_prefix else relative_to_r2_source(str(path), r2_source)
        row_id = f"knowledge.{source_prefix or 'source'}.doc.{stable_hash(source_ref, raw[:4000])}"
        if row_id in seen:
            continue
        title = extract_markdown_title(raw, ref)
        excerpt = extract_doc_signal(raw, r2_source, 1400)
        question = f"What workflow or usage knowledge is documented in `{source_ref}`?"
        answer = f"Document `{source_ref}` ({title}) provides this source-grounded guidance:\n{excerpt}"
        rows.append(knowledge_row(
            row_id,
            f"{source_prefix or 'source'}.doc",
            question,
            answer,
            [source_ref],
            r2_source,
            tags=["source-doc", source_prefix or "radare2-source"],
            title=title,
        ))
        seen.add(row_id)
    return rows


def build_plugin_source_knowledge(r2_source: Path, seen: set[str], limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    plugin_paths = sorted((r2_source / "libr").glob("*/p/**/*.c"))
    for path in plugin_paths:
        if len(rows) >= limit:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        plugins = re.findall(r"\br_(asm|anal|bin|io|fs|lang|crypto|debug|egg|core)_plugin_([A-Za-z0-9_]+)\b", text)
        if not plugins:
            continue
        ref = relative_to_r2_source(str(path), r2_source)
        row_id = f"knowledge.plugin.source.{stable_hash(ref, plugins[:4])}"
        if row_id in seen:
            continue
        plugin_list = ", ".join(f"{kind}:{name}" for kind, name in sorted(set(plugins))[:8])
        answer = (
            f"Source `{ref}` defines radare2 plugin symbols: {plugin_list}. "
            "This records the plugin family and symbol names only; behavior should be learned from focused command evidence or concise docs."
        )
        rows.append(knowledge_row(
            row_id,
            "plugin.source",
            f"Which radare2 plugin symbols are defined by `{ref}`?",
            answer,
            [ref],
            r2_source,
            tags=["source", "plugins", *sorted({kind for kind, _ in plugins})],
            title=f"radare2 plugin source {ref}",
        ))
        seen.add(row_id)
    return rows


def discover_fixture_triage_plans(r2_source: Path, seen: set[str], limit: int) -> list[dict[str, Any]]:
    base = r2_source / "test" / "bins"
    if not base.is_dir():
        return []
    allowed_prefixes = (
        "test/bins/elf/", "test/bins/pe/", "test/bins/mach0/", "test/bins/arm/",
        "test/bins/wasm/", "test/bins/java/", "test/bins/fs/", "test/bins/zip/",
        "test/bins/pdb/", "test/bins/cil/", "test/bins/mz/", "test/bins/nes/",
    )
    plans = []
    for path in sorted(base.rglob("*")):
        if len(plans) >= limit:
            break
        if not path.is_file():
            continue
        ref = relative_to_r2_source(str(path), r2_source)
        if not ref.startswith(allowed_prefixes):
            continue
        if any(part in ref for part in ("/src/", "/headers/", "/fuzzed/", ".github/")):
            continue
        try:
            if path.stat().st_size > 8 * 1024 * 1024:
                continue
        except OSError:
            continue
        plan_id = f"fixture.triage.{stable_hash(ref)}"
        row_id = f"knowledge.experiment.{plan_id}"
        if row_id in seen:
            continue
        plans.append({
            "id": plan_id,
            "topic": "fixture.triage",
            "fixture": ref,
            "commands": ["iI", "ij"],
            "checks": [{"type": "line_count_gte", "value": 2}],
            "question": f"What initial radare2 triage facts can be verified for `{ref}`?",
            "answer": "Run `iI` for human-readable loader metadata and `ij` for JSON metadata. Keep the result as observed evidence because fixture format coverage depends on enabled bin plugins.",
            "source_refs": [ref],
            "tags": ["experiment", "fixture-triage", ref.split("/")[2] if len(ref.split("/")) > 2 else "test-bins"],
        })
    return plans




def iter_source_scan_files(r2_source: Path) -> list[Path]:
    paths: list[Path] = []
    for root_name in SOURCE_SCAN_ROOTS:
        root = r2_source / root_name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in {".c", ".h", ".inc", ".inc.c"}:
                continue
            try:
                if path.stat().st_size > 500_000:
                    continue
            except OSError:
                continue
            paths.append(path)
    return paths


def source_signal_line(line: str) -> str:
    apis = re.findall(r"\b(?:r|R)_[A-Za-z0-9_]+\b", line)
    markers = []
    if "%s" in line:
        markers.append("format-%s")
    if "TODO" in line:
        markers.append("TODO")
    if "XXX" in line:
        markers.append("XXX")
    if "*" in line and "printf" in line:
        markers.append("formatted-output")
    parts = []
    compact = re.sub(r"\s+", " ", line.strip())[:120]
    if apis:
        parts.append("apis=" + ",".join(sorted(set(apis))[:6]))
    if markers:
        parts.append("markers=" + ",".join(markers))
    if "TODO" in line or "XXX" in line:
        parts.append("note=" + compact)
    if not parts:
        parts.append("signal=" + compact[:90])
    return "; ".join(parts)


def collect_source_hits(r2_source: Path, regex: str, limit_files: int = 40, max_lines_per_file: int = 3) -> list[dict[str, Any]]:
    pattern = re.compile(regex)
    hits: list[dict[str, Any]] = []
    for path in iter_source_scan_files(r2_source):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        ref = relative_to_r2_source(str(path), r2_source)
        line_hits = []
        for lineno, line in enumerate(lines, 1):
            if not pattern.search(line):
                continue
            line_hits.append({"line": lineno, "summary": source_signal_line(line)})
            if len(line_hits) >= max_lines_per_file:
                break
        if line_hits:
            hits.append({"ref": ref, "hits": line_hits})
            if len(hits) >= limit_files:
                break
    return hits


def source_scan_verification(regex: str, hits: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "source-scan-ok",
        "checks": [{"type": "source_regex", "value": regex, "passed": bool(hits)}],
        "source_file_count": len(hits),
        "source_hit_count": sum(len(item.get("hits", [])) for item in hits),
    }


def source_scan_signal_summary(hits: list[dict[str, Any]], limit: int = 8) -> str:
    api_counts: dict[str, int] = {}
    marker_counts: dict[str, int] = {}
    signal_examples: list[str] = []
    for item in hits:
        for hit in item.get("hits", []):
            summary = str(hit.get("summary", ""))
            for part in summary.split("; "):
                if part.startswith("apis="):
                    for api in part.removeprefix("apis=").split(","):
                        if api:
                            api_counts[api] = api_counts.get(api, 0) + 1
                elif part.startswith("markers="):
                    for marker in part.removeprefix("markers=").split(","):
                        if marker:
                            marker_counts[marker] = marker_counts.get(marker, 0) + 1
                elif part and part not in signal_examples:
                    signal_examples.append(part)
    lines = []
    if api_counts:
        apis = ", ".join(api for api, _ in sorted(api_counts.items(), key=lambda item: (-item[1], item[0]))[:limit])
        lines.append(f"Observed API variants: {apis}.")
    if marker_counts:
        markers = ", ".join(marker for marker, _ in sorted(marker_counts.items(), key=lambda item: (-item[1], item[0]))[:limit])
        lines.append(f"Observed sink markers: {markers}.")
    if signal_examples:
        lines.append("Representative signal shapes: " + "; ".join(signal_examples[:4]) + ".")
    if not lines:
        lines.append("The scan matched the configured source pattern, but no stable non-location signal summary was extracted.")
    return "\n".join(lines)


def source_scan_ref(kind: str, name: str) -> str:
    return f"radare2-{kind}:{safe_id_part(name)}"


def existing_r2r_source_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in merge_rows(read_jsonl(KNOWLEDGE_PATH), []):
        if knowledge_category(row) != "verified-radare2-workflows":
            continue
        ref = primary_source_ref(row)
        if ref:
            counts[ref] = counts.get(ref, 0) + 1
    return counts


def build_source_xref_knowledge(r2_source: Path, seen: set[str], limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in SOURCE_XREF_TARGETS:
        if len(rows) >= limit:
            break
        term = str(target["term"])
        hits = collect_source_hits(r2_source, r"\b" + re.escape(term) + r"[A-Za-z0-9_]*\b", 24, 2)
        if not hits:
            continue
        row_id = f"knowledge.xref.{safe_id_part(term)}"
        if row_id in seen:
            continue
        hit_count = sum(len(item.get("hits", [])) for item in hits)
        stable_ref = source_scan_ref("api", term)
        answer = (
            f"A current radare2 source scan found `{term}`-family usage with {hit_count} signal hits across {len(hits)} files. "
            "The training row intentionally omits file and line references because the codebase changes frequently.\n\n"
            f"Stable signal summary:\n{source_scan_signal_summary(hits)}\n\n"
            f"Agentic use: {target['guidance']} Re-run the source scan on the target checkout when exact locations are needed."
        )
        rows.append(knowledge_row(
            row_id,
            str(target["topic"]),
            f"How should a radare2 agent reason about the `{term}` API family?",
            answer,
            [stable_ref],
            r2_source,
            tags=list(target.get("tags", [])),
            verification=source_scan_verification(term, hits),
            title=str(target["title"]),
        ))
        seen.add(row_id)
    return rows


def r2bugs_report_block(r2_source: Path) -> tuple[str, int]:
    sections: list[str] = []
    for pattern in BUG_HUNT_PATTERNS:
        name = str(pattern["name"])
        regex = str(pattern["regex"])
        hits = collect_source_hits(r2_source, regex, 48, 3)
        if not hits:
            continue
        verification = source_scan_verification(regex, hits)
        summary = source_scan_signal_summary(hits).replace("\n", "\n  ")
        sections.append(
            "\n".join([
                f"## {name}",
                "",
                "Status: unconfirmed source-audit lead. This is not a vulnerability claim until a reproducer or patch proves the risk.",
                f"Stable ref: `radare2-audit:{safe_id_part(name)}`",
                f"Pattern: `{regex}`",
                f"Current scan: {verification['source_hit_count']} signals across {verification['source_file_count']} files.",
                "",
                "Stable signal summary:",
                f"  {summary}",
                "",
                f"Audit guidance: {pattern['guidance']}",
                "",
                "Verification required before fixing or filing:",
                "- Re-run the scan on the target radare2 checkout.",
                "- Trace whether user-controlled or binary-controlled input reaches the sink.",
                "- Confirm the behavior with a minimal r2/r2r reproducer or a narrowly scoped source patch.",
            ])
        )
    body = "\n\n".join(sections) if sections else "No source-audit leads matched the current scan patterns."
    block = (
        f"{R2BUGS_START}\n"
        "This block is generated by `make agentic`. Keep manual notes outside the markers.\n"
        "Source bug findings are intentionally kept out of the training knowledge base.\n\n"
        f"{body}\n"
        f"{R2BUGS_END}\n"
    )
    return block, len(sections)


def write_text_if_changed(path: Path, text: str) -> bool:
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


def write_r2bugs_report(r2_source: Path) -> tuple[int, bool]:
    block, count = r2bugs_report_block(r2_source)
    header = (
        "# R2BUGS\n\n"
        "Potential radare2 source bugs and source-audit leads found by agentic scans.\n"
        "Confirmed bugs should include a reproducer, impact notes, and fix status.\n"
    )
    try:
        current = R2BUGS_PATH.read_text(encoding="utf-8")
    except OSError:
        current = header + "\n"
    if R2BUGS_START in current and R2BUGS_END in current:
        before = current.split(R2BUGS_START, 1)[0].rstrip()
        after = current.split(R2BUGS_END, 1)[1].lstrip()
        text = before + "\n\n" + block
        if after:
            text += "\n" + after
    else:
        text = current.rstrip() + "\n\n" + block
    return count, write_text_if_changed(R2BUGS_PATH, text)


def iter_r2r_test_files(r2_source: Path, source_counts: dict[str, int] | None = None) -> list[Path]:
    base = r2_source / "test" / "db"
    if not base.is_dir():
        return []
    buckets: list[list[Path]] = []
    for category in R2R_TEST_CATEGORIES:
        root = base / category
        if not root.is_dir():
            continue
        category_paths: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            try:
                ref = path.resolve().relative_to(base.resolve()).as_posix()
                if ref in R2R_SKIP_TEST_FILES or path.stat().st_size > 240_000:
                    continue
            except OSError:
                continue
            category_paths.append(path)
        if category_paths:
            buckets.append(category_paths)
    paths: list[Path] = []
    max_len = max((len(bucket) for bucket in buckets), default=0)
    for index in range(max_len):
        for bucket in buckets:
            if index < len(bucket):
                paths.append(bucket[index])
    if source_counts:
        indexed_paths = list(enumerate(paths))
        indexed_paths.sort(key=lambda item: (source_counts.get(relative_to_r2_source(str(item[1]), r2_source), 0), item[0]))
        paths = [path for _, path in indexed_paths]
    return paths


def parse_r2r_test_file(path: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    tests: list[dict[str, str]] = []
    block: dict[str, str] = {}
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if line.strip() == "RUN":
            if block:
                tests.append(block)
                block = {}
            idx += 1
            continue
        match = re.match(r"^([A-Z0-9_]+)=(.*)$", line)
        if not match:
            idx += 1
            continue
        key, value = match.group(1), match.group(2)
        if value == "<<EOF":
            idx += 1
            body: list[str] = []
            while idx < len(lines) and lines[idx] != "EOF":
                body.append(lines[idx])
                idx += 1
            block[key] = "\n".join(body)
            if idx < len(lines) and lines[idx] == "EOF":
                idx += 1
            continue
        block[key] = value
        idx += 1
    if block:
        tests.append(block)
    return tests


def normalize_r2r_fixture(raw: str, r2_source: Path) -> str | None:
    fixture = raw.strip() or "-"
    if fixture in ("-", "--"):
        return fixture
    if fixture.startswith("bins/"):
        fixture = "test/" + fixture
    if fixture.startswith("test/bins/"):
        return fixture if (r2_source / fixture).is_file() else None
    if fixture.startswith(R2R_SAFE_URI_PREFIXES):
        return fixture
    return None


def safe_r2r_value(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.:+,-]+$", value)) and ".." not in value


def safe_r2r_eval(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]+=[A-Za-z0-9_.:+,-]+$", value)) and ".." not in value


def safe_r2r_args(raw: str) -> list[str] | None:
    if not raw.strip():
        return []
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return None
    safe: list[str] = []
    one_arg = {"-a", "-b", "-B", "-m", "-s", "-k", "-F"}
    no_arg = {"-A", "-n", "-nn", "-w", "-M", "-1"}
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token in no_arg:
            safe.append(token)
            idx += 1
            continue
        if token == "-e" and idx + 1 < len(tokens) and safe_r2r_eval(tokens[idx + 1]):
            safe.extend([token, tokens[idx + 1]])
            idx += 2
            continue
        if token.startswith("-e") and safe_r2r_eval(token[2:]):
            safe.append(token)
            idx += 1
            continue
        if token in one_arg and idx + 1 < len(tokens) and safe_r2r_value(tokens[idx + 1]):
            safe.extend([token, tokens[idx + 1]])
            idx += 2
            continue
        short = re.match(r"^-(a|b|B|m|s|k|F)(.+)$", token)
        if short and safe_r2r_value(short.group(2)):
            safe.append(token)
            idx += 1
            continue
        return None
    return safe


def r2r_commands_from_test(test: dict[str, str]) -> list[str]:
    raw = test.get("CMDS", "").strip("\n")
    if len(raw) > 2400:
        return []
    commands = [line.rstrip() for line in raw.splitlines()] if "\n" in raw else [raw.strip()]
    commands = [cmd for cmd in commands if cmd.strip() and not cmd.lstrip().startswith("#")]
    max_commands = int(os.environ.get("AGENTIC_R2R_MAX_COMMANDS", "14"))
    if len(commands) > max_commands:
        return []
    return commands


def is_safe_r2r_command_sequence(commands: list[str], test_ref: str) -> bool:
    if not commands:
        return False
    test_key = test_ref.removeprefix("test/db/")
    if test_key in R2R_SKIP_TEST_FILES or any(part in test_key for part in ("dbg", "debug")):
        return False
    unsafe_needles = (
        "http://", "https://", "r2.syscmd", "syscmd", "r2pipe.open",
        "LD_PRELOAD", "/tmp/", "/home/", "{R2_SOURCE}", "${R2_SOURCE}",
    )
    for command in commands:
        stripped = command.strip()
        if not stripped:
            continue
        if stripped in {"q", "q!"}:
            return False
        if stripped.startswith(("!", "#!", ":!")) or re.search(r"(^|[;|&])\s*!", stripped):
            return False
        if any(needle in stripped for needle in unsafe_needles):
            return False
        if re.match(r"^(ood|doo|dc|dcu|ds|dmi|dmh|dp|dk)\b", stripped):
            return False
        if re.search(r"\bbins/", stripped):
            return False
    return True


def r2r_expected_checks(expect: str, r2_source: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    seen_values: set[str] = set()
    for raw_line in expect.splitlines():
        line = sanitize_text(clean_output(raw_line).strip(), r2_source)
        if not line or len(line) < 3 or len(line) > 180:
            continue
        if set(line) <= set("-=_ "):
            continue
        if line.startswith(("WARN:", "INFO:")):
            continue
        value = line[:160]
        if value in seen_values:
            continue
        checks.append({"type": "contains", "value": value})
        seen_values.add(value)
        if len(checks) >= 2:
            break
    return checks


def r2r_command_family(commands: list[str]) -> str:
    for command in commands:
        stripped = command.strip()
        if not stripped.startswith(("e ", "?e", "? ", "-a", "-b")):
            return safe_id_part(stripped.split()[0])[:32]
    return safe_id_part(commands[0].split()[0])[:32]


def humanize_r2r_name(name: str) -> str:
    subject = re.sub(r"[`'\"]", "", name.strip())
    subject = subject.replace("_", " ").replace("/", " ")
    subject = re.sub(r"\s+", " ", subject).strip()
    return subject or "this radare2 workflow"


def r2r_fixture_context(fixture: str) -> str:
    if fixture in {"-", "--"}:
        return "in a scratch radare2 session"
    if is_r2_uri_fixture(fixture):
        return f"using `{fixture}`"
    return f"on `{fixture}`"


def r2r_command_topic(commands: list[str]) -> str:
    topics = []
    for command in commands:
        stripped = command.strip()
        if not stripped or stripped.startswith(("e ", "?e", "? ", "-a", "-b")):
            continue
        token = stripped.split()[0]
        if token not in topics:
            topics.append(token)
        if len(topics) >= 3:
            break
    if not topics and commands:
        topics.append(commands[0].strip().split()[0])
    if not topics:
        return "radare2 commands"
    if len(topics) == 1:
        return f"`{topics[0]}`"
    if len(topics) == 2:
        return f"`{topics[0]}` and `{topics[1]}`"
    return f"`{topics[0]}`, `{topics[1]}`, and `{topics[2]}`"


def r2r_workflow_question(name: str, fixture: str, category: str, commands: list[str]) -> str:
    subject = humanize_r2r_name(name)
    context = r2r_fixture_context(fixture)
    command_topic = r2r_command_topic(commands)
    if category == "esil":
        return f"How do I use radare2 ESIL to evaluate {subject} {context}?"
    if category == "anal":
        return f"How do I use radare2 to analyze {subject} {context}?"
    if category == "formats":
        return f"How do I inspect {subject} metadata with radare2 {context}?"
    if category == "asm":
        return f"How do I use radare2 assembly or disassembly commands for {subject} {context}?"
    if category == "io":
        return f"How do I use radare2 I/O commands to check {subject} {context}?"
    if category == "cmd":
        return f"How do I use {command_topic} in radare2 to check {subject} {context}?"
    return f"How do I use radare2 to check {subject} {context}?"


def r2r_workflow_answer(fixture: str, commands: list[str], expected: str, verification: Verification, r2_source: Path) -> str:
    display_commands = "\n".join(f"- `{cmd}`" for cmd in commands)
    if fixture in {"-", "--"}:
        opener = "Start radare2 without a target file and run this command sequence."
    elif is_r2_uri_fixture(fixture):
        opener = f"Open `{fixture}` in radare2 and run this command sequence."
    else:
        opener = f"Open `{fixture}` in radare2 and run this command sequence."
    return (
        f"{opener}\n\n"
        f"Command sequence:\n{display_commands}\n\n"
        f"Use these output fragments as the validation signal: {expected}.\n\n"
        f"Observed output excerpt:\n{output_excerpt(sanitize_text(verification.output, r2_source), 1400)}"
    )


def build_r2r_test_knowledge(r2_bin: Path, r2_source: Path, timeout: int, seen: set[str], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    source_counts = existing_r2r_source_counts()
    max_rows_per_source = int(os.environ.get("AGENTIC_R2R_MAX_ROWS_PER_SOURCE", "2"))
    for path in iter_r2r_test_files(r2_source, source_counts):
        if len(rows) >= limit:
            break
        test_ref = relative_to_r2_source(str(path), r2_source)
        if max_rows_per_source > 0 and source_counts.get(test_ref, 0) >= max_rows_per_source:
            continue
        category = test_ref.split("/")[2] if test_ref.startswith("test/db/") and len(test_ref.split("/")) > 2 else "test"
        rows_from_file = 0
        rows_per_file = max(1, int(os.environ.get("AGENTIC_R2R_ROWS_PER_FILE", "1")))
        for index, test in enumerate(parse_r2r_test_file(path), 1):
            if len(rows) >= limit or rows_from_file >= rows_per_file:
                break
            if test.get("BROKEN") or test.get("EXPECT_ERR"):
                continue
            name = test.get("NAME", path.name).strip() or path.name
            fixture = normalize_r2r_fixture(test.get("FILE", "-"), r2_source)
            if not fixture:
                continue
            r2_args = safe_r2r_args(test.get("ARGS", ""))
            if r2_args is None:
                continue
            commands = r2r_commands_from_test(test)
            if not is_safe_r2r_command_sequence(commands, test_ref):
                continue
            checks = r2r_expected_checks(test.get("EXPECT", ""), r2_source)
            if not checks:
                continue
            row_id = "knowledge.r2r.%s.%03d.%s" % (
                safe_id_part(test_ref.removeprefix("test/db/").replace("/", ".")),
                index,
                stable_hash(name, fixture, "\n".join(commands)),
            )
            if row_id in seen:
                continue
            if fixture not in ("-", "--") and not is_r2_uri_fixture(fixture) and not Path(fixture_path({"fixture": fixture}, r2_source)).is_file():
                continue
            entry = {
                "id": row_id,
                "kind": "reasoning_task",
                "fixture": fixture,
                "r2_args": r2_args,
                "starter_commands": commands,
                "checks": checks,
                "answer": "",
                "question": name,
            }
            verification = run_entry(entry, r2_bin, r2_source, timeout)
            seen.add(row_id)
            if not verification.ok:
                continue
            source_refs = [test_ref]
            if fixture.startswith("test/bins/"):
                source_refs.append(fixture)
            expected = "; ".join(str(check["value"]) for check in checks)
            family = r2r_command_family(commands)
            answer = r2r_workflow_answer(fixture, commands, expected, verification, r2_source)
            rows.append(knowledge_row(
                row_id,
                f"r2r.{category}.{safe_id_part(path.name)}",
                r2r_workflow_question(name, fixture, category, commands),
                answer,
                source_refs,
                r2_source,
                tags=["r2r-test", category, family, "verified"],
                verification=verification_summary(verification, r2_source, r2_bin),
                title=name,
                kind="agentic_experiment",
            ))
            rows_from_file += 1
            source_counts[test_ref] = source_counts.get(test_ref, 0) + 1
    return rows, []


def build_experiment_knowledge(r2_bin: Path, r2_source: Path, timeout: int, seen: set[str], limit: int, discover_fixtures: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    plans = list(GROWTH_EXPERIMENT_PLANS)
    if discover_fixtures:
        plans.extend(discover_fixture_triage_plans(r2_source, seen, max(limit * 4, 8)))
    for plan in plans:
        if len(rows) >= limit:
            break
        row_id = f"knowledge.experiment.{plan['id']}"
        if row_id in seen:
            continue
        fixture = str(plan.get("fixture", "-"))
        if fixture not in ("-", "--") and not is_r2_uri_fixture(fixture) and not Path(fixture_path({"fixture": fixture}, r2_source)).is_file():
            continue
        entry = {
            "id": row_id,
            "kind": "reasoning_task",
            "fixture": fixture,
            "starter_commands": list(plan["commands"]),
            "checks": list(plan.get("checks", [{"type": "nonempty"}])),
            "answer": plan["answer"],
            "question": plan["question"],
        }
        verification = run_entry(entry, r2_bin, r2_source, timeout)
        if verification.ok:
            commands = "\n".join(f"- `{cmd}`" for cmd in plan["commands"])
            answer = f"{plan['answer']}\n\nVerified command sequence:\n{commands}\n\nEvidence excerpt:\n{output_excerpt(sanitize_text(verification.output, r2_source), 1800)}"
            rows.append(knowledge_row(
                row_id,
                str(plan["topic"]),
                str(plan["question"]),
                answer,
                list(plan.get("source_refs", [])),
                r2_source,
                tags=list(plan.get("tags", [])),
                verification=verification_summary(verification, r2_source, r2_bin),
                title=str(plan["topic"]),
                kind="agentic_experiment",
            ))
            seen.add(row_id)
        else:
            pending.append(growth_pending(row_id, "experiment", str(plan["question"]), verification, r2_source, list(plan.get("source_refs", []))))
            seen.add(row_id)
    return rows, pending


def parse_online_urls() -> list[str]:
    raw = os.environ.get("AGENTIC_ONLINE_URLS", "").strip()
    if not raw:
        return DEFAULT_ONLINE_URLS
    return [url for url in re.split(r"[\s,]+", raw) if url]


def build_online_knowledge(args: argparse.Namespace, r2_source: Path, seen: set[str], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if args.online == "off" or limit <= 0:
        return [], []
    rows: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for url in parse_online_urls():
        if len(rows) >= limit:
            break
        try:
            req = Request(url, headers={"User-Agent": "r2ai-model-agentic-dataset/1.0"})
            with urlopen(req, timeout=args.online_timeout) as res:
                raw = res.read(220_000)
                ctype = res.headers.get("content-type", "")
            text = raw.decode("utf-8", errors="replace")
            if "html" in ctype or "<html" in text[:500].lower():
                text = html_to_text(text)
            text = extract_doc_signal(text, r2_source, 1400)
            if len(text.strip()) < 80:
                continue
            row_id = f"knowledge.online.{stable_hash(url, text[:1200])}"
            if row_id in seen:
                continue
            rows.append(knowledge_row(
                row_id,
                "online.radare2",
                f"What radare2 knowledge is available from `{url}`?",
                f"Fetched external radare2 documentation from `{url}`:\n{text}",
                [url],
                r2_source,
                tags=["online", "book" if "book.rada.re" in url else "radare2"],
                title=url,
            ))
            seen.add(row_id)
        except (OSError, HTTPError, URLError, TimeoutError) as exc:
            if args.online == "required":
                pending.append({
                    "id": f"knowledge.online.failed.{stable_hash(url)}",
                    "kind": "online",
                    "question": f"Fetch external radare2 resource `{url}`",
                    "reason": sanitize_text(str(exc), r2_source),
                    "status": "fetch-failed",
                    "source_refs": [url],
                })
    return rows, pending


def filter_suppressed_pending_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suppressed = human_suppressed_pending_ids()
    if not suppressed:
        return rows
    return [row for row in rows if str(row.get("id", "")) not in suppressed]


def growth_pending(row_id: str, kind: str, question: str, verification: Verification, r2_source: Path, source_refs: list[str]) -> dict[str, Any]:
    return {
        "id": row_id,
        "kind": kind,
        "question": sanitize_text(question, r2_source),
        "reason": verification.reason or verification.status,
        "status": verification.status,
        "returncode": verification.returncode,
        "source_refs": [sanitize_text(ref, r2_source) for ref in source_refs],
        "output_excerpt": output_excerpt(sanitize_text(verification.output, r2_source), 600),
    }


def add_limited(target: list[dict[str, Any]], rows: list[dict[str, Any]], budget: int) -> None:
    remaining = budget - len(target)
    if remaining > 0:
        target.extend(rows[:remaining])


def build_autonomous_knowledge(r2_bin: Path, r2_source: Path, timeout: int, args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    budget = max(0, args.growth_budget)
    seen = existing_knowledge_ids()
    rows: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []

    baseline = (
        human_response_knowledge_rows(r2_source)
        + build_help_knowledge(r2_bin, r2_source, timeout, seen)
        + build_r2js_script_knowledge(r2_source, seen)
    )
    for row in baseline:
        row_id = str(row.get("id", ""))
        if row_id and row_id not in seen and len(rows) < budget:
            rows.append(row)
            seen.add(row_id)

    section_budget = max(1, args.section_budget)
    builders = [
        ("help", lambda n: build_help_frontier(r2_bin, r2_source, timeout, seen, n)),
        ("command-grammar", lambda n: build_command_grammar_knowledge(r2_bin, r2_source, timeout, seen, n)),
        ("experiments", lambda n: build_experiment_knowledge(r2_bin, r2_source, timeout, seen, n, args.discover_fixtures)),
        ("source-xrefs", lambda n: (build_source_xref_knowledge(r2_source, seen, n), [])),
        ("r2r-tests", lambda n: build_r2r_test_knowledge(r2_bin, r2_source, timeout, seen, n)),
        ("source-docs", lambda n: (build_doc_knowledge(iter_source_docs(r2_source), r2_source, "source", r2_source, seen, n), [])),
        ("plugin-source", lambda n: (build_plugin_source_knowledge(r2_source, seen, n), [])),
        ("book-docs", lambda n: (build_doc_knowledge(iter_local_book_docs(r2_source), Path(os.environ.get("R2_BOOK_SOURCE", str(r2_source.parent / "radare2-book"))), "book", r2_source, seen, n), [])),
        ("online", lambda n: build_online_knowledge(args, r2_source, seen, n)),
    ]
    for _name, builder in builders:
        remaining = budget - len(rows)
        if remaining <= 0:
            break
        new_rows, new_pending = builder(min(section_budget, remaining))
        pending.extend(new_pending)
        add_limited(rows, new_rows, budget)
    return rows, pending


def write_knowledge_base(r2_bin: Path, r2_source: Path, timeout: int, args: argparse.Namespace) -> tuple[int, int, int, list[dict[str, Any]], list[dict[str, Any]], Path | None]:
    bug_count, bugs_changed = write_r2bugs_report(r2_source)
    status = "updated" if bugs_changed else "checked"
    print(f"r2bugs {status}: {bug_count} source-audit leads in {repo_path_ref(R2BUGS_PATH)}")
    rows, pending = build_autonomous_knowledge(r2_bin, r2_source, timeout, args)
    new_count, total_count, accepted_rows, run_path = write_knowledge_outputs(rows, pending, args)
    return new_count, total_count, len(pending), accepted_rows, pending, run_path


def selected_datasets(name: str) -> list[str]:
    if name == "all":
        return list(DATASETS)
    if name not in DATASETS:
        raise SystemExit(f"unknown dataset {name}")
    return [name]


def build(args: argparse.Namespace) -> int:
    if args.skip_seeds and args.dataset != "all":
        raise SystemExit("--skip-seeds only applies to the full agentic knowledge build")

    r2_bin = pick_r2_bin(args.r2_bin)
    r2_source = Path(args.r2_source)
    all_pending: list[dict[str, Any]] = []
    seeds_checked = False
    if not args.skip_seeds:
        seeds_checked = True
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
                write_verified_jsonl(paths["verified"], verified_rows)
                write_jsonl_if_changed(paths["pending"], pending_rows)
    if not args.dry_run and args.dataset == "all":
        new_count, total_count, pending_count, accepted_rows, pending_rows, run_path = write_knowledge_base(r2_bin, r2_source, args.timeout, args)
        print(f"knowledge agentic {new_count} new rows, {total_count} total rows, {pending_count} pending checks")
        if run_path:
            print(f"knowledge run shard {repo_path_ref(run_path)}")
        print_new_knowledge_rows(accepted_rows, pending_rows)
        command_memory_limit = int(os.environ.get(
            "AGENTIC_KNOWLEDGE_COMMAND_MEMORY_LIMIT",
            os.environ.get("AGENTIC_COMMANDS_MEMORY_LIMIT", "24"),
        ))
        if command_memory_limit > 0:
            knowledge_command_topics = knowledge_command_memory_topics(command_memory_limit)
            topic_count, queued_count = queue_command_memory_topics(
                knowledge_command_topics,
                True,
                COMMANDS_KNOWLEDGE_TOPICS_PATH,
            )
            print(
                f"knowledge command memory topics {topic_count} written to "
                f"{repo_path_ref(COMMANDS_KNOWLEDGE_TOPICS_PATH)}, queued {queued_count} for make memory"
            )
    if not args.dry_run and seeds_checked:
        write_human_tsv(ROOT / "data" / "agentic-review" / "generated-failures.tsv", all_pending)
    return 0 if not all_pending else 1


def repo_path_ref(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def restore_knowledge_command(command_line: Any, r2_bin: Path) -> tuple[list[str] | None, str]:
    if not isinstance(command_line, list) or not command_line:
        return None, "no command_line"
    args: list[str] = []
    for idx, raw_arg in enumerate(command_line):
        arg = str(raw_arg)
        if arg in {"<generated-r2js-script>", "<tmp-path>", "<home-path>"}:
            return None, f"cannot restore sanitized placeholder {arg}"
        if idx == 0 and arg in {"radare2", "r2"}:
            args.append(str(r2_bin))
        else:
            args.append(arg)
    return args, ""


def safe_knowledge_verify_command(args: list[str]) -> tuple[bool, str]:
    for idx, arg in enumerate(args):
        if arg != "-c" or idx + 1 >= len(args):
            continue
        command = args[idx + 1].strip()
        if command.startswith(("!", "#!", ":!")) or re.search(r"(^|[;&|])\s*!", command):
            return False, "stored command invokes a shell escape"
        if "http://" in command or "https://" in command:
            return False, "stored command reaches the network"
    return True, ""


def knowledge_output_hashes(output: str, r2_source: Path) -> set[str]:
    sanitized = sanitize_text(output, r2_source)
    candidates = {
        sanitized,
        output_excerpt(sanitized, 1800),
        output_excerpt(sanitized, 1200),
    }
    return {hashlib.sha256(candidate.encode("utf-8")).hexdigest() for candidate in candidates}


def verify_knowledge_row(row: dict[str, Any], r2_bin: Path, r2_source: Path, timeout: int) -> tuple[str, str]:
    verification = row.get("verification")
    if not isinstance(verification, dict):
        return "skipped", "no verification metadata"
    args, reason = restore_knowledge_command(verification.get("command_line"), r2_bin)
    if args is None:
        return "skipped", reason
    safe, reason = safe_knowledge_verify_command(args)
    if not safe:
        return "skipped", reason
    start = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            cwd=str(r2_source if r2_source.is_dir() else ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "failed", f"timed out after {timeout}s"
    elapsed = int((time.monotonic() - start) * 1000)
    output = clean_output(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        return "failed", f"returncode={proc.returncode} elapsed_ms={elapsed}"
    checks = verification.get("checks")
    if isinstance(checks, list) and checks:
        ok, _checked, check_reason = evaluate_checks(output, checks)
        if not ok:
            return "failed", check_reason
    expected_hash = str(verification.get("output_sha256", ""))
    if expected_hash and expected_hash not in knowledge_output_hashes(output, r2_source):
        return "failed", "output_sha256 mismatch"
    return "ok", f"elapsed_ms={elapsed}"


def verify_knowledge(args: argparse.Namespace) -> int:
    r2_bin = pick_r2_bin(args.r2_bin)
    r2_source = Path(args.r2_source)
    rows = read_jsonl(KNOWLEDGE_PATH)
    if args.ids:
        wanted = set(args.ids)
        rows = [row for row in rows if str(row.get("id", "")) in wanted]
    if args.limit > 0:
        rows = rows[:args.limit]

    counts = {"ok": 0, "failed": 0, "skipped": 0}
    for row in rows:
        row_id = str(row.get("id", "<missing-id>"))
        status, reason = verify_knowledge_row(row, r2_bin, r2_source, args.timeout)
        counts[status] = counts.get(status, 0) + 1
        if status == "ok":
            print(f"ok knowledge {row_id}")
        elif status == "failed":
            print(f"failed knowledge {row_id}: {reason}")
        elif args.verbose:
            print(f"skipped knowledge {row_id}: {reason}")
    print(f"knowledge verify {counts['ok']} ok, {counts['failed']} failed, {counts['skipped']} skipped, {len(rows)} checked")
    return 1 if counts["failed"] else 0


def sanitize_obj(value: Any, r2_source: Path) -> Any:
    if isinstance(value, str):
        return sanitize_text(value, r2_source)
    if isinstance(value, list):
        return [sanitize_obj(item, r2_source) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_obj(item, r2_source) for key, item in value.items()}
    return value


def agentic_pending_paths() -> list[Path]:
    paths = [config["pending"] for config in DATASETS.values()]
    paths.append(KNOWLEDGE_PENDING_PATH)
    return paths


def load_agentic_pending() -> tuple[dict[Path, list[dict[str, Any]]], list[tuple[Path, dict[str, Any]]]]:
    loaded: dict[Path, list[dict[str, Any]]] = {}
    tasks: list[tuple[Path, dict[str, Any]]] = []
    for path in agentic_pending_paths():
        rows = filter_suppressed_pending_rows(read_jsonl(path))
        loaded[path] = rows
        for row in rows:
            tasks.append((path, row))
    return loaded, tasks


def short_value(value: Any, limit: int = 1000) -> str:
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    text = str(value or "").strip()
    if len(text) > limit:
        return text[:limit] + "\n[truncated]"
    return text


def print_pending_task(idx: int, total: int, path: Path, row: dict[str, Any]) -> None:
    print("\n" + "=" * 72)
    print(f"Pending {idx}/{total}: {row.get('id', '<unknown>')}")
    print(f"File: {repo_path_ref(path)}")
    for key in ("kind", "dataset", "status", "reason", "fixture", "source_refs"):
        if row.get(key):
            print(f"{key}: {short_value(row.get(key), 600)}")
    print("\nQuestion:")
    print(short_value(row.get("question"), 2000))
    if row.get("proposed_answer"):
        print("\nProposed answer:")
        print(short_value(row.get("proposed_answer"), 1600))
    if row.get("output_excerpt"):
        print("\nEvidence / failure output:")
        print(short_value(row.get("output_excerpt"), 1600))


def read_pending_answer() -> tuple[str, str]:
    print("\nEnter the human answer. Finish with a single '.' line.")
    print("Commands: /skip keeps it pending, /drop clears without an answer, /quit stops.")
    try:
        first = input("> ")
    except EOFError:
        return "quit", ""
    command = first.strip().lower()
    if not command:
        return "skip", ""
    if command in {"/skip", "skip"}:
        return "skip", ""
    if command in {"/drop", "drop"}:
        return "drop", ""
    if command in {"/quit", "quit", "/q", "q"}:
        return "quit", ""
    lines = [first]
    while True:
        try:
            line = input("... ")
        except EOFError:
            break
        if line == ".":
            break
        lines.append(line)
    answer = "\n".join(lines).strip()
    if not answer:
        return "skip", ""
    return "answer", answer


def remove_pending_row(rows: list[dict[str, Any]], row: dict[str, Any]) -> bool:
    for idx, item in enumerate(rows):
        if item == row:
            rows.pop(idx)
            return True
    row_id = row.get("id")
    if row_id:
        for idx, item in enumerate(rows):
            if item.get("id") == row_id:
                rows.pop(idx)
                return True
    return False


def list_pending_tasks(tasks: list[tuple[Path, dict[str, Any]]]) -> None:
    if not tasks:
        print("no agentic pending tasks")
        return
    for idx, (path, row) in enumerate(tasks, 1):
        question = short_value(row.get("question"), 120).replace("\n", " ")
        print(f"{idx}. {repo_path_ref(path)} {row.get('id', '<unknown>')}: {question}")


def pending(args: argparse.Namespace) -> int:
    r2_source = Path(args.r2_source)
    loaded, tasks = load_agentic_pending()
    if args.list:
        list_pending_tasks(tasks)
        return 0
    if not tasks:
        print("no agentic pending tasks")
        return 0
    if not sys.stdin.isatty():
        raise SystemExit("agentic pending review requires an interactive terminal; use --list to inspect pending rows")

    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    response_path = Path(args.response_log)
    responses: list[dict[str, Any]] = []
    answered = dropped = skipped = 0

    for idx, (path, row) in enumerate(tasks, 1):
        if row not in loaded[path]:
            continue
        print_pending_task(idx, len(tasks), path, row)
        action, answer = read_pending_answer()
        if action == "quit":
            print("stopped pending review")
            break
        if action == "skip":
            skipped += 1
            continue
        if not remove_pending_row(loaded[path], row):
            skipped += 1
            continue
        response = {
            "id": row.get("id", ""),
            "action": "answered" if action == "answer" else "dropped",
            "kind": row.get("kind", ""),
            "question": sanitize_text(str(row.get("question", "")), r2_source),
            "human_answer": sanitize_text(answer, r2_source),
            "reviewed_at": reviewed_at,
            "source_pending": repo_path_ref(path),
            "original": sanitize_obj(row, r2_source),
        }
        responses.append(response)
        if action == "answer":
            answered += 1
        else:
            dropped += 1

    for path, rows in loaded.items():
        write_jsonl_if_changed(path, rows)
    promoted = 0
    if responses:
        previous = read_jsonl(response_path)
        write_jsonl_if_changed(response_path, previous + responses)
        promoted = promote_knowledge_rows(human_response_knowledge_rows(r2_source, responses))

    remaining = sum(len(rows) for rows in loaded.values())
    print(f"agentic pending: {answered} answered, {dropped} dropped, {skipped} skipped, {remaining} remaining")
    if responses:
        print(f"wrote responses to {repo_path_ref(response_path)}")
    if promoted:
        print(f"promoted {promoted} human-reviewed rows into {repo_path_ref(KNOWLEDGE_PATH)}")
    return 0


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
    build_parser.add_argument("--growth-budget", type=int, default=int(os.environ.get("AGENTIC_GROWTH_BUDGET", "24")))
    build_parser.add_argument("--section-budget", type=int, default=int(os.environ.get("AGENTIC_SECTION_BUDGET", "4")))
    build_parser.add_argument("--online", choices=["auto", "off", "required"], default=os.environ.get("AGENTIC_ONLINE", "auto"))
    build_parser.add_argument("--online-timeout", type=float, default=float(os.environ.get("AGENTIC_ONLINE_TIMEOUT", "2.0")))
    build_parser.add_argument("--discover-fixtures", action="store_true", default=os.environ.get("AGENTIC_DISCOVER_FIXTURES", "0").lower() in {"1", "true", "yes", "on"})
    build_parser.add_argument("--skip-seeds", action="store_true", help="skip fixed seed dataset verification and only grow agentic knowledge")
    build_parser.add_argument("--dry-run", action="store_true")
    build_parser.set_defaults(func=build)

    verify_parser = sub.add_parser("verify-knowledge", help="verify executable checks stored in agentic knowledge")
    verify_parser.add_argument("--r2-bin", default=None)
    verify_parser.add_argument("--r2-source", default=str(DEFAULT_R2_SOURCE))
    verify_parser.add_argument("--timeout", type=int, default=20)
    verify_parser.add_argument("--limit", type=int, default=int(os.environ.get("AGENTIC_VERIFY_LIMIT", "0")))
    verify_parser.add_argument("--id", dest="ids", action="append", default=[], help="verify only this knowledge row id; can be repeated")
    verify_parser.add_argument("--verbose", action="store_true", help="print skipped rows too")
    verify_parser.set_defaults(func=verify_knowledge)

    pending_parser = sub.add_parser("pending", help="manually answer and clear agentic pending rows")
    pending_parser.add_argument("--list", action="store_true", help="list pending rows without prompting")
    pending_parser.add_argument("--response-log", default=str(HUMAN_RESPONSES_PATH))
    pending_parser.add_argument("--r2-source", default=str(DEFAULT_R2_SOURCE))
    pending_parser.set_defaults(func=pending)

    commands_parser = sub.add_parser("commands", help="build the agentic radare2 command grammar database")
    commands_parser.add_argument("--r2-bin", default=None)
    commands_parser.add_argument("--r2-source", default=str(DEFAULT_R2_SOURCE))
    commands_parser.add_argument("--timeout", type=int, default=20)
    commands_parser.add_argument("--limit", type=int, default=int(os.environ.get("AGENTIC_COMMANDS_LIMIT", "240")))
    commands_parser.add_argument("--variants-per-block", type=int, default=int(os.environ.get("AGENTIC_COMMANDS_VARIANTS_PER_BLOCK", "8")))
    commands_parser.add_argument("--memory-limit", type=int, default=int(os.environ.get("AGENTIC_COMMANDS_MEMORY_LIMIT", "24")))
    commands_parser.add_argument("--queue-memory", action=argparse.BooleanOptionalAction, default=False)
    commands_parser.add_argument("--ai", choices=["auto", "off", "required"], default=os.environ.get("AGENTIC_COMMANDS_AI", "auto"))
    commands_parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o"))
    commands_parser.add_argument("--temperature", type=float, default=float(os.environ.get("AGENTIC_COMMANDS_TEMPERATURE", "0.2")))
    commands_parser.set_defaults(func=build_agentic_command_database)

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
