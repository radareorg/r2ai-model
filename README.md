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
knowledge base. The `ok r2cmd`/`ok r2js` lines are the fixed seed verification
checks; the `knowledge new rows` section lists the actual newly learned row ids
and categories for that invocation. Each run deduplicates existing row ids,
chooses unseen frontier items, promotes human-reviewed pending answers, runs
radare2 commands against fixtures under `R2_SOURCE/test/bins`, scans radare2
source/docs/plugins/r2js scripts, optionally fetches online radare2/book pages,
and writes accepted rows into the curated aggregate JSONL plus a per-run audit
shard. The aggregate is deduped by row id and content fingerprint, prunes generic
fixture-triage rows, rejects navigation-heavy online pages, stores plugin source
learning as concise symbol summaries, and extracts only signal-bearing doc lines.
Local home paths, temp files, and usernames are sanitized; fixture and source
references are stored relative to `R2_SOURCE`.

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
AGENTIC_GROWTH_BUDGET=64 AGENTIC_SECTION_BUDGET=6 make agentic
AGENTIC_ONLINE=off make agentic
AGENTIC_ONLINE=required AGENTIC_ONLINE_URLS=https://book.rada.re/ make agentic
R2_BOOK_SOURCE=../radare2-book make agentic
AGENTIC_DISCOVER_FIXTURES=1 make agentic
```

Broad fixture discovery is off by default because it can produce repetitive
low-value rows. Enable `AGENTIC_DISCOVER_FIXTURES=1` only when you explicitly
want broad fixture coverage for audit or exploration. `AGENTIC_SECTION_BUDGET`
limits how many rows any one growth section can contribute in a run, so the
agentic loop can stop early instead of filling the budget with low-diversity
rows. Aggregate category caps such as `AGENTIC_MAX_PLUGIN_SOURCE_ROWS`,
`AGENTIC_MAX_SOURCE_DOC_ROWS`, and `AGENTIC_MAX_WORKFLOW_ROWS` prevent saturated
sections from growing forever.

When agentic checks need human confirmation, run:

```sh
make agentic-pending
```

The prompt records answers in `data/agentic-review/human-responses.jsonl`,
promotes answered rows into `data/agentic-knowledge/knowledge.jsonl`, and
removes answered or dropped rows from the `pending-human.jsonl` queues. Answered
or dropped pending ids are suppressed in future growth runs, so `make agentic`
does not recreate the same human task. Use `/skip` to keep a row pending,
`/drop` to clear it without an answer, and `/quit` to stop reviewing.

Optional AI proposal mode:

```sh
OPENAI_API_KEY=... ./agentic-dataset.py propose --count 20
```

AI proposals are written as agentic-only pending rows and must still pass the
local verifier before they are promoted to training data.
