# Learning Data

Use the agentic loop to discover and register new radare2 knowledge rows.

```sh
make agentic
make agentic-commands
```

This runs `agentic-dataset.py build --skip-seeds`. It skips the fixed seed
dataset verification and grows `data/agentic-knowledge/knowledge.jsonl`.

Useful controls:

```sh
AGENTIC_GROWTH_BUDGET=64 AGENTIC_SECTION_BUDGET=6 make agentic
AGENTIC_ONLINE=off make agentic
AGENTIC_DISCOVER_FIXTURES=1 make agentic
make agentic-commands
```

Generated knowledge is stored in:

* `data/agentic-knowledge/knowledge.jsonl`: deduplicated aggregate training rows.
* `data/agentic-knowledge/runs/`: per-run audit shards.
* `data/agentic-knowledge/pending-human.jsonl`: rows needing human review.
* `data/agentic-commands/`: command grammar rows, training export, and memory topics.
* `R2BUGS.md`: generated source-audit leads kept out of training data.

Do not train from every run shard directly. The aggregate file already dedupes
and quality-filters accepted rows.


## Human Memory

Use `make memory` when the agent has a topic that needs clarification from the
human. The answer is stored as source memory and exported as chat JSONL for the
training merge.

```sh
make memory
make agentic-memory MEMORY_FORMAT=json > question.json
make agentic-memory-file < answer.json
make memory-add TOPIC="radare2 command composition" QUESTION="How should repeat prefixes combine with ESIL stepping?" TAGS="radare2,esil"
make memory-export
```
