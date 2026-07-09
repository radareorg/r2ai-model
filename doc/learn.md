# Learning Data

Use the agentic loop to discover and register new radare2 knowledge rows.

```sh
make agentic
```

This runs `agentic-dataset.py build --skip-seeds`. It skips the fixed seed
dataset verification and grows `data/agentic-knowledge/knowledge.jsonl`.

Useful controls:

```sh
AGENTIC_GROWTH_BUDGET=64 AGENTIC_SECTION_BUDGET=6 make agentic
AGENTIC_ONLINE=off make agentic
AGENTIC_DISCOVER_FIXTURES=1 make agentic
```

Generated knowledge is stored in:

* `data/agentic-knowledge/knowledge.jsonl`: deduplicated aggregate training rows.
* `data/agentic-knowledge/runs/`: per-run audit shards.
* `data/agentic-knowledge/pending-human.jsonl`: rows needing human review.
* `R2BUGS.md`: generated source-audit leads kept out of training data.

Do not train from every run shard directly. The aggregate file already dedupes
and quality-filters accepted rows.
