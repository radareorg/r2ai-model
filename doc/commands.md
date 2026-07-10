# Agentic Commands

`make agentic-commands` builds a reusable radare2 command grammar dataset. It
reads radare2 help output, the full `?*` command-line grammar, and the existing
command database, then writes command explanations and memory questions.

```sh
make agentic-commands
make memory
make agentic-commands
```

The second `make agentic-commands` run folds accepted `make memory` answers
back into the command database. Matching rows become `human-reviewed`, include a
`Human memory:` section, and are exported into the training JSONL. Answered
memory topics are not queued again.

Files:

* `data/agentic-commands/commands.jsonl`: command database with syntax,
  decomposition, status, source refs, and verification metadata.
* `data/agentic-commands/verified.jsonl`: chat-format training export.
* `data/agentic-commands/memory-topics.jsonl`: questions generated from weak
  command explanations and command usage mined from the knowledge database.
* `data/agentic-commands/knowledge-memory-topics.jsonl`: questions that
  `make agentic` mined from existing `data/agentic-knowledge/knowledge.jsonl`
  workflow rows.
* `data/memory/topics.jsonl`: queued questions consumed by `make memory` or
  `make agentic-memory-file`.

The command rows explain how command strings are composed. For example, `afl` is
explained as `a` for analysis, `f` for function under analysis, and `l` for list
under `af`, so `afl` lists analyzed functions. `make agentic-commands` also
mines existing agentic knowledge rows for real workflow commands like `pdf @
main`, `afi@...~noret[1]`, and ESIL stepping sequences, then queues questions
when those expressions are missing, weak, or composed from modifiers the command
database should learn.

AI support is optional. With `OPENAI_API_KEY` set, the command builder can ask an
OpenAI-compatible model for better human-memory questions about weak rows:

```sh
AGENTIC_COMMANDS_AI=auto make agentic-commands
AGENTIC_COMMANDS_AI=required OPENAI_MODEL=gpt-4o make agentic-commands
```

Offline mode still works and uses deterministic heuristics:

```sh
AGENTIC_COMMANDS_AI=off make agentic-commands
```
