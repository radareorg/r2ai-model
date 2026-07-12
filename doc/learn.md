# Learning Data

Use the agentic loop to discover and register new radare2 knowledge rows.

```sh
r2ai-model learn
r2ai-model refresh-commands
```

`learn` runs `agentic-dataset.py build --skip-seeds`. It skips fixed seed
dataset verification and grows `data/agentic-knowledge/knowledge.jsonl`.
It does not merge datasets or fine-tune. A later `train` includes the updated
aggregate automatically.

Useful controls:

```sh
r2ai-model learn --growth-budget 64 --section-budget 6
r2ai-model learn --online off
r2ai-model learn --discover-fixtures
r2ai-model refresh-commands
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

Use `r2ai-model queue` when an agent has a topic that needs clarification from the
human. The answer is stored as source memory and exported as chat JSONL for the
training merge.

```sh
r2ai-model queue "radare2 command composition" --question "How should repeat prefixes combine with ESIL stepping?" --tags radare2,esil
r2ai-model next --format json > question.json
r2ai-model answer < answer.json
r2ai-model export
```
