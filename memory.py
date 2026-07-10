#!/usr/bin/env python3
"""Collect human memory notes and export them as training rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
MEMORY_DIR = ROOT / "data" / "memory"
TOPICS_PATH = MEMORY_DIR / "topics.jsonl"
MEMORY_PATH = MEMORY_DIR / "memory.jsonl"
TRAINING_PATH = MEMORY_DIR / "verified.jsonl"

SYSTEM_PROMPT = (
    "You are a radare2 assistant trained from human corrections. "
    "Prefer the corrected human memory when answering."
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_hash(*parts: object, length: int = 16) -> str:
    data = "\n".join(str(part) for part in parts)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:length]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid JSONL in {path}:{lineno}") from exc
            if isinstance(item, dict):
                rows.append(item)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def split_tags(value: str | None) -> list[str]:
    if not value:
        return []
    tags: list[str] = []
    for item in value.replace(";", ",").split(","):
        tag = item.strip()
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def one_line(value: str) -> str:
    return " ".join(value.strip().split())


def memory_messages(topic: str, highlight: str, details: str) -> list[dict[str, str]]:
    answer = f"{highlight.strip()}\n\nDetails:\n{details.strip()}"
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"What did the human clarify about {topic.strip()}?"},
        {"role": "assistant", "content": answer.strip()},
    ]


def make_memory_row(
    topic: str,
    highlight: str,
    details: str,
    tags: list[str],
    source: str,
    question: str = "",
) -> dict[str, Any]:
    topic = one_line(topic)
    highlight = one_line(highlight)
    details = details.strip()
    fingerprint = stable_hash(topic, highlight, details)
    row_id = f"memory.{stable_hash(topic, fingerprint)}"
    return {
        "content_fingerprint": fingerprint,
        "created_at": utc_now(),
        "details": details,
        "highlight": highlight,
        "id": row_id,
        "kind": "human_memory",
        "messages": memory_messages(topic, highlight, details),
        "question": one_line(question) if question else "",
        "source": {"channel": source},
        "status": "accepted",
        "tags": tags,
        "topic": topic,
    }


def export_training_rows() -> int:
    rows = []
    seen: set[str] = set()
    for row in read_jsonl(MEMORY_PATH):
        if row.get("status") != "accepted":
            continue
        row_id = str(row.get("id", ""))
        messages = row.get("messages")
        if not row_id or row_id in seen or not isinstance(messages, list):
            continue
        seen.add(row_id)
        rows.append(
            {
                "content_fingerprint": row.get("content_fingerprint", ""),
                "id": row_id,
                "kind": "human_memory",
                "messages": messages,
                "source_refs": ["data/memory/memory.jsonl"],
                "tags": row.get("tags", []),
                "topic": row.get("topic", ""),
            }
        )
    write_jsonl(TRAINING_PATH, rows)
    return len(rows)


def add_topic(args: argparse.Namespace) -> int:
    topic = one_line(args.topic)
    if not topic:
        print("missing topic", file=sys.stderr)
        return 1
    question = one_line(args.question or topic)
    rows = read_jsonl(TOPICS_PATH)
    topic_id = f"topic.{stable_hash(topic, question)}"
    for row in rows:
        if row.get("id") == topic_id:
            print(f"already queued {topic_id}")
            return 0
    row = {
        "created_at": utc_now(),
        "id": topic_id,
        "question": question,
        "source": {"channel": args.source},
        "status": "pending",
        "tags": split_tags(args.tags),
        "topic": topic,
    }
    append_jsonl(TOPICS_PATH, row)
    print(f"queued {topic_id}")
    return 0


def remember(args: argparse.Namespace) -> int:
    topic = one_line(args.topic)
    highlight = one_line(args.highlight)
    details = args.details
    if details == "-":
        details = sys.stdin.read()
    details = (details or "").strip()
    if not topic or not highlight or not details:
        print("topic, highlight, and details are required", file=sys.stderr)
        return 1
    row = make_memory_row(
        topic=topic,
        highlight=highlight,
        details=details,
        tags=split_tags(args.tags),
        source=args.source,
        question=args.question or "",
    )
    existing = read_jsonl(MEMORY_PATH)
    existing_ids = {str(item.get("id")) for item in existing}
    if row["id"] in existing_ids:
        print(f"already remembered {row['id']}")
    else:
        append_jsonl(MEMORY_PATH, row)
        print(f"remembered {row['id']}")
    count = export_training_rows()
    print(f"exported {count} memory training rows to {TRAINING_PATH.relative_to(ROOT)}")
    return 0


def print_topics(args: argparse.Namespace) -> int:
    rows = read_jsonl(TOPICS_PATH)
    if not args.all:
        rows = [row for row in rows if row.get("status") == "pending"]
    if not rows:
        print("no memory topics")
        return 0
    for row in rows:
        tags = ",".join(row.get("tags") or [])
        suffix = f" tags={tags}" if tags else ""
        print(f"{row.get('status', 'pending')} {row.get('id')} {row.get('topic')}{suffix}")
        question = str(row.get("question") or "").strip()
        if question and question != row.get("topic"):
            print(f"  {question}")
    return 0


def pending_topics() -> list[dict[str, Any]]:
    return [row for row in read_jsonl(TOPICS_PATH) if row.get("status") == "pending"]


def memory_answer_template(topic: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": topic.get("id", ""),
        "highlight": "one sentence with the corrected or clarified fact",
        "details": "full explanation, examples, commands, caveats, and any context the model must learn",
        "tags": topic.get("tags") or ["radare2", "memory"],
    }


def agentic_memory_payload(topic: dict[str, Any], pending_count: int) -> dict[str, Any]:
    template = memory_answer_template(topic)
    return {
        "id": topic.get("id", ""),
        "pending_count": pending_count,
        "question": topic.get("question") or topic.get("topic") or "",
        "source": topic.get("source", {}),
        "submit": {
            "stdin": "make agentic-memory-file < answer.json",
            "file": "make agentic-memory-file FILE=answer.json",
        },
        "tags": topic.get("tags") or [],
        "topic": topic.get("topic", ""),
        "answer_template": template,
    }


def print_agentic_memory(args: argparse.Namespace) -> int:
    pending = pending_topics()
    if not pending:
        if args.format == "json":
            print(json.dumps({"pending_count": 0, "status": "empty"}, ensure_ascii=False, indent=2))
        else:
            print("no pending memory topics")
        return 0
    current = pending[0]
    payload = agentic_memory_payload(current, len(pending))
    if args.format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(f"Memory topic: {payload['topic']}")
    print(f"Topic id: {payload['id']}")
    print(f"Pending: {payload['pending_count']}")
    tags = ",".join(payload.get("tags") or [])
    if tags:
        print(f"Tags: {tags}")
    print("\nQuestion:")
    print(payload["question"])
    print("\nAnswer JSON template:")
    print(json.dumps(payload["answer_template"], ensure_ascii=False, indent=2))
    print("\nSubmit with stdin:")
    print("  make agentic-memory-file < answer.json")
    print("\nSubmit with a file:")
    print("  make agentic-memory-file FILE=answer.json")
    return 0


def load_answer_payloads(path: str) -> list[dict[str, Any]]:
    if path in {"", "-"}:
        raw = sys.stdin.read()
    else:
        raw = Path(path).read_text(encoding="utf-8")
    raw = raw.strip()
    if not raw:
        raise SystemExit("empty memory answer payload")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"memory answer payload must be JSON: {exc}") from exc
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return parsed
    raise SystemExit("memory answer payload must be a JSON object or list of objects")


def tags_from_payload(value: Any, fallback: list[str]) -> list[str]:
    if isinstance(value, list):
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    if isinstance(value, str):
        tags = split_tags(value)
        if tags:
            return tags
    return fallback


def source_from_payload(value: Any, fallback: str) -> str:
    if isinstance(value, dict) and value.get("channel"):
        return str(value.get("channel"))
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def remember_payload(payload: dict[str, Any], rows: list[dict[str, Any]], args: argparse.Namespace) -> str:
    topic_id = str(payload.get("id") or payload.get("topic_id") or payload.get("memory_topic_id") or "").strip()
    if not topic_id:
        raise SystemExit("memory answer payload is missing id")
    current = next((row for row in rows if row.get("id") == topic_id), None)
    if current is None:
        raise SystemExit(f"memory topic id not found: {topic_id}")
    if current.get("status") == "answered" and current.get("memory_id"):
        return str(current.get("memory_id"))
    highlight = one_line(str(payload.get("highlight") or ""))
    details_value = payload.get("details") or ""
    if isinstance(details_value, list):
        details = "\n".join(str(item) for item in details_value).strip()
    else:
        details = str(details_value).strip()
    if not highlight or not details:
        raise SystemExit("memory answer payload requires highlight and details")
    tags = tags_from_payload(payload.get("tags"), list(current.get("tags") or ["radare2", "memory"]))
    memory = make_memory_row(
        topic=str(current.get("topic") or ""),
        highlight=highlight,
        details=details,
        tags=tags,
        source=source_from_payload(payload.get("source"), args.source),
        question=str(current.get("question") or ""),
    )
    existing_ids = {str(row.get("id")) for row in read_jsonl(MEMORY_PATH)}
    if memory["id"] not in existing_ids:
        append_jsonl(MEMORY_PATH, memory)
    current["status"] = "answered"
    current["answered_at"] = utc_now()
    current["memory_id"] = memory["id"]
    return str(memory["id"])


def answer_file(args: argparse.Namespace) -> int:
    payloads = load_answer_payloads(args.file)
    rows = read_jsonl(TOPICS_PATH)
    remembered: list[str] = []
    for payload in payloads:
        remembered.append(remember_payload(payload, rows, args))
    write_jsonl(TOPICS_PATH, rows)
    count = export_training_rows()
    for memory_id in remembered:
        print(f"remembered {memory_id}")
    print(f"exported {count} memory training rows to {TRAINING_PATH.relative_to(ROOT)}")
    return 0



def prompt_line(prompt: str, default: str = "") -> str:
    if default:
        value = input(f"{prompt} [{default}]: ").strip()
        return value or default
    return input(f"{prompt}: ").strip()


def prompt_details() -> str:
    print("Details, finish with a single '.' line:")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == ".":
            break
        lines.append(line)
    return "\n".join(lines).strip()


def ask(args: argparse.Namespace) -> int:
    rows = read_jsonl(TOPICS_PATH)
    pending = [row for row in rows if row.get("status") == "pending"]
    if not pending:
        if not sys.stdin.isatty():
            print("no pending memory topics")
            return 0
        print("No pending memory topics. Create one now or press enter to stop.")
        topic = prompt_line("Topic")
        if not topic:
            return 0
        add_args = argparse.Namespace(
            topic=topic,
            question=prompt_line("Question", topic),
            tags=prompt_line("Tags", "radare2,memory"),
            source=args.source,
        )
        add_topic(add_args)
        rows = read_jsonl(TOPICS_PATH)
        pending = [row for row in rows if row.get("status") == "pending"]
    if not pending:
        return 0

    current = pending[0]
    print(f"Topic: {current.get('topic')}")
    print(f"Question: {current.get('question') or current.get('topic')}")
    print("Commands: /skip keeps it pending, /drop removes it, /quit stops.")
    highlight = prompt_line("Highlight")
    if highlight == "/quit":
        return 0
    if highlight in {"/skip", ""}:
        print("kept pending")
        return 0
    if highlight == "/drop":
        current["status"] = "dropped"
        current["answered_at"] = utc_now()
        write_jsonl(TOPICS_PATH, rows)
        print(f"dropped {current.get('id')}")
        return 0

    details = prompt_details()
    if not details:
        print("empty details, kept pending")
        return 1
    default_tags = ",".join(current.get("tags") or ["radare2", "memory"])
    tags = split_tags(prompt_line("Tags", default_tags))
    memory = make_memory_row(
        topic=str(current.get("topic") or ""),
        highlight=highlight,
        details=details,
        tags=tags,
        source=args.source,
        question=str(current.get("question") or ""),
    )
    existing_ids = {str(row.get("id")) for row in read_jsonl(MEMORY_PATH)}
    if memory["id"] not in existing_ids:
        append_jsonl(MEMORY_PATH, memory)
    current["status"] = "answered"
    current["answered_at"] = utc_now()
    current["memory_id"] = memory["id"]
    write_jsonl(TOPICS_PATH, rows)
    count = export_training_rows()
    print(f"remembered {memory['id']}")
    print(f"exported {count} memory training rows to {TRAINING_PATH.relative_to(ROOT)}")
    return 0


def export_command(args: argparse.Namespace) -> int:
    count = export_training_rows()
    print(f"exported {count} memory training rows to {TRAINING_PATH.relative_to(ROOT)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")

    ask_parser = sub.add_parser("ask", help="answer the next pending topic interactively")
    ask_parser.add_argument("--source", default="terminal", help="memory transport name")
    ask_parser.set_defaults(func=ask)

    add_parser = sub.add_parser("add-topic", help="queue a topic for human clarification")
    add_parser.add_argument("topic")
    add_parser.add_argument("--question", default="", help="specific question to ask")
    add_parser.add_argument("--tags", default="", help="comma-separated tags")
    add_parser.add_argument("--source", default="terminal", help="memory transport name")
    add_parser.set_defaults(func=add_topic)

    list_parser = sub.add_parser("list", help="list pending memory topics")
    list_parser.add_argument("--all", action="store_true", help="include answered and dropped topics")
    list_parser.set_defaults(func=print_topics)

    next_parser = sub.add_parser("next", help="print the next pending topic and non-interactive answer template")
    next_parser.add_argument("--format", choices=["text", "json"], default="text")
    next_parser.set_defaults(func=print_agentic_memory)

    answer_file_parser = sub.add_parser("answer-file", help="record one or more JSON memory answers from stdin or a file")
    answer_file_parser.add_argument("--file", default="-", help="JSON answer file, or '-' for stdin")
    answer_file_parser.add_argument("--source", default="agentic-memory", help="memory transport name")
    answer_file_parser.set_defaults(func=answer_file)

    remember_parser = sub.add_parser("remember", help="record a memory directly")
    remember_parser.add_argument("--topic", required=True)
    remember_parser.add_argument("--highlight", required=True)
    remember_parser.add_argument("--details", required=True, help="details text, or '-' to read stdin")
    remember_parser.add_argument("--question", default="", help="question this memory answers")
    remember_parser.add_argument("--tags", default="", help="comma-separated tags")
    remember_parser.add_argument("--source", default="terminal", help="memory transport name")
    remember_parser.set_defaults(func=remember)

    export_parser = sub.add_parser("export-training", help="export accepted memories to chat JSONL")
    export_parser.set_defaults(func=export_command)

    parser.set_defaults(func=ask, source="terminal")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
