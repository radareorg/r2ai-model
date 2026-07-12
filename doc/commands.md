# Agentic Commands

`make agentic-commands` builds a reusable radare2 command grammar dataset. It
executes the installed radare2 `?*` help, refreshes the full help snapshot, and
writes evidence-backed command, modifier, command-family, and memory rows.

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
  scope, family relationships, executable workflow uses, status, source refs,
  and verification metadata.
* `data/agentic-commands/families.jsonl`: chunked `Usage:` blocks that retain
  contextual keys, legends, examples, sibling variants, and scope labels.
* `data/agentic-commands/selection.jsonl`: balanced inverse examples that map a
  documented user intent to one representative command per family, plus
  commands observed in executable workflows.
* `data/agentic-commands/focused-workflows.jsonl`: dense lessons for a reviewed
  set of analysis, ESIL, and debugger commands, plus executable multi-command
  workflows. Each workflow is emitted only when its observed output satisfies
  deterministic checks.
* `data/agentic-commands/verified.jsonl`: chat-format training export combining
  trusted individual, command-family, intent-selection, focused-command, and
  workflow rows.
* `data/radare2/sources/all_commands.txt`: current sanitized output of `?*`.
* `data/agentic-commands/memory-topics.jsonl`: questions generated from weak
  command explanations and command usage mined from the knowledge database.
* `data/agentic-commands/knowledge-memory-topics.jsonl`: questions that
  `make agentic` mined from existing `data/agentic-knowledge/knowledge.jsonl`
  workflow rows.
* `data/memory/topics.jsonl`: queued questions consumed by `make memory` or
  `make agentic-memory-file`.

The command rows keep exact syntax and evidence lines separate from inferred
letter meanings. Unknown letters no longer make authoritative help unusable,
and they are never guessed. Prefix relationships connect parents, siblings, and
children such as `af`, `afl`, `aflj`, and `aflq`. Executable rows already in the
agentic knowledge database add checked workflow expressions such as `pdf @ main`
or filtered ESIL sequences. Family rows preserve local legends such as the
`pxA` color-map keys while explicitly marking them context-local, preventing a
legend token like `_C` from being learned as a standalone shell command.

The build has deterministic quality gates: duplicate IDs, truncated `?*`
output, unverified documented rows, malformed conversations, and accidental
`needs-memory` promotion fail the command. The index records the help hash,
coverage, trust counts, focused curriculum counts, workflow linkage, rejected
workflow evidence, and the radare2 versions used for help and executable
checks. Command help follows the active installed radare2. Executable workflows
prefer the source-tree build so the executable and libraries have matching
ABIs; a workflow can explicitly require the active build when it verifies newer
behavior. Set
`AGENTIC_COMMANDS_ARGS="--memory-limit 0 --no-queue-memory"` when refreshing the
dataset without changing the human-review queue.

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
