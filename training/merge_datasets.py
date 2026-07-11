#!/usr/bin/env python3
"""Merge chat datasets into a uniform training-only JSONL file."""

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator


SUPPORTED_ROLES = {"system", "user", "assistant", "tool"}


def training_row(row: Any, source: Path, lineno: int) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError(f"{source}:{lineno}: expected a JSON object")
    messages = row.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError(f"{source}:{lineno}: missing non-empty messages list")

    normalized = []
    for index, message in enumerate(messages):
        location = f"{source}:{lineno}:messages[{index}]"
        if not isinstance(message, dict):
            raise ValueError(f"{location}: expected a JSON object")
        role = message.get("role")
        content = message.get("content")
        tool_calls = message.get("tool_calls") or []
        if role not in SUPPORTED_ROLES:
            raise ValueError(f"{location}: unsupported role {role!r}")
        if not isinstance(tool_calls, list):
            raise ValueError(f"{location}: tool_calls must be a list")
        has_tool_call = role == "assistant" and bool(tool_calls)
        if not isinstance(content, str) or (
            not content.strip() and not has_tool_call
        ):
            raise ValueError(f"{location}: content must be a non-empty string")
        normalized.append({
            "role": role,
            "content": content,
            "name": str(message.get("name") or ""),
            "tool_call_id": str(message.get("tool_call_id") or ""),
            "tool_calls": tool_calls,
        })

    tools = row.get("tools") or []
    if not isinstance(tools, list):
        raise ValueError(f"{source}:{lineno}: tools must be a list")
    return {"messages": normalized, "tools": tools}


def read_training_rows(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        for lineno, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON") from exc
            yield training_row(row, path, lineno)


def merge_datasets(inputs: list[Path], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=output.name + ".",
        suffix=".tmp",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        try:
            for path in inputs:
                count = 0
                for row in read_training_rows(path):
                    stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                    count += 1
                total += count
                print(f"merged {count} rows from {path}")
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    os.replace(temporary, output)
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()
    total = merge_datasets(args.inputs, args.output)
    print(f"merged {total} rows into {args.output}")


if __name__ == "__main__":
    main()
