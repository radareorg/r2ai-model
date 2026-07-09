# r2ai-model

Collection of data sources to generate a dataset for training and finetuning LLM models to use radare2.

## Organization

Dataset is stored in Q/A form (Question/Answer) separating them by tabs (TSV) where the question is phrased in English and the answer is an r2 oneliner to be executed by r2ai in auto mode.

* / -> root directory, scripts to generate raw QA
* `data/radare2_ok.tsv` -> validated statements
* `data/radare2_todo.tsv` -> unanswered questions
* data/Attic/ -> already processed files
* data/sources -> unfiltered data sources to be used to generate questions

## Agentic generation

The manual review flow remains the default `make` target. The autonomous
agentic path is opt-in:

```sh
make agentic
```

This runs `agentic-dataset.py build`. It still verifies the seed companion
datasets, but it also grows `data/agentic-knowledge/` as an append-only
knowledge base. Each run deduplicates existing row ids, chooses unseen frontier
items, runs radare2 commands against fixtures under `R2_SOURCE/test/bins`, scans
radare2 source/docs/plugins/r2js scripts, optionally fetches online radare2/book
pages, and writes newly learned rows into both the aggregate JSONL and a
per-run shard. Local home paths, temp files, and usernames are sanitized; fixture
and source references are stored relative to `R2_SOURCE`.

Verified companion datasets live in:

* `data/radare2-agentic/` -> action to r2 command examples with evidence.
* `data/r2js/` -> examples and Q/A for radare2's QuickJS runtime.
* `data/reasoning-long/` -> multi-step reverse engineering, forensics,
  firmware, and vulnerability research tasks.
* `data/agentic-knowledge/` -> append-only generated knowledge, per-run shards,
  source/book/online/plugin facts, and verified workflows/challenges.
* `data/agentic-review/` -> agentic-only questions and failed checks for human review.

Useful controls:

```sh
AGENTIC_GROWTH_BUDGET=64 make agentic
AGENTIC_ONLINE=off make agentic
AGENTIC_ONLINE=required AGENTIC_ONLINE_URLS=https://book.rada.re/ make agentic
R2_BOOK_SOURCE=../radare2-book make agentic
```

When agentic checks need human confirmation, run:

```sh
make agentic-pending
```

The prompt records answers in `data/agentic-review/human-responses.jsonl`
and removes answered or dropped rows from the `pending-human.jsonl` queues.
Use `/skip` to keep a row pending, `/drop` to clear it without an answer, and
`/quit` to stop reviewing.

Optional AI proposal mode:

```sh
OPENAI_API_KEY=... ./agentic-dataset.py propose --count 20
```

AI proposals are written as agentic-only pending rows and must still pass the
local verifier before they are promoted to training data.
