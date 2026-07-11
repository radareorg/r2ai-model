# Datasets

This repository currently has two parallel dataset systems:

1. A legacy/manual TSV pipeline for collecting and reviewing question/command
   pairs.
2. A verified agentic JSONL pipeline for executable examples, source-grounded
   knowledge, command grammar, long-form reasoning, and human corrections.

The inventory below describes the current worktree. Generated row counts may
change after running the agentic, memory, review, or merge commands.

## Active training datasets

`training/Makefile` builds the agentic training dataset by concatenating these
seven files:

| Dataset | Current rows | Purpose |
| --- | ---: | --- |
| `data/radare2/radare2_train.jsonl` | 363 | Classic question-to-radare2-command examples |
| `data/radare2-agentic/verified.jsonl` | 10 | Locally executed and checked command examples |
| `data/r2js/verified.jsonl` | 5 | Embedded JavaScript/r2js examples |
| `data/reasoning-long/verified.jsonl` | 4 | Multi-step reverse-engineering workflows |
| `data/agentic-knowledge/knowledge.jsonl` | 349 | Deduplicated source-, documentation-, test-, and experiment-derived knowledge |
| `data/agentic-commands/verified.jsonl` | 240 | Training export of command grammar explanations |
| `data/memory/verified.jsonl` | 9 | Exported human corrections |
| **Current source total** | **980** | Expected result of a fresh merge |

The merge validates every conversation and writes a uniform training-only row
containing `messages`. It does not shuffle, split, or deduplicate across the
seven sources. Rebuild it with:

```sh
make -C training merge-agentic-dataset
```

Source identifiers, provenance, and verification details remain in the source
datasets. They are intentionally omitted from the merged artifact because the
training loader consumes only `messages`, and heterogeneous verification check
values cannot be represented by one inferred Arrow schema.

The current generated artifact contains all 980 rows from the seven sources.
The active training configs use a 2,048-token limit, which contains the current
longest row (1,836 tokens with the local Qwen chat template) without truncation.
Batch padding remains dynamic, so shorter command examples retain their natural
length until collation.
At preprocessing time, `apply_chat_template(tokenize=True)` adds and tokenizes
the model-specific role markers, separators, and end-of-turn tokens in one step,
avoiding duplicated special tokens.
Training labels use `-100` outside assistant response spans. System prompts,
user questions, and model-specific assistant prompt markers remain in
`input_ids` as context but do not contribute directly to the loss.

There is no explicit train/validation/test split. `training/config.yaml`
currently points to the classic 363-row dataset, while
`training/config.minicpm5.yaml` points to the merged agentic dataset. Set the
desired `dataset.path` before custom training.

## Training row structure

Training files use JSON Lines: one JSON object per line. The common shape is:

```json
{
  "id": "optional stable id",
  "kind": "dataset type",
  "topic": "optional topic",
  "tags": ["radare2"],
  "source_refs": ["relative/source/reference"],
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "..."}
  ],
  "verification": {
    "status": "ok",
    "returncode": 0,
    "command_line": ["..."],
    "checks": [{"type": "contains", "value": "..."}],
    "output_sha256": "...",
    "output_excerpt": "..."
  }
}
```

The classic dataset contains only `messages`. Verified datasets add stable
identifiers, provenance, tags, topics, fixtures, and verification metadata.
The training code principally consumes the `messages` array.

## Classic radare2 data

The `data/radare2/` directory contains the original TSV workflow, its raw
sources, generated review queues, compiled chat data, and function-calling
variants.

### Main classic pipeline

* `radare2_ok.tsv` is the reviewed `q<TAB>a` source. It currently has 366
  normal Q/A rows and two malformed one-column records.
* `radare2_enriched.tsv` has 365 data records with `q`, `a`, `thinking`, and
  `breakdown` columns. Two records do not have usable Q/A fields.
* `radare2_train.jsonl` is the resulting set of 363 valid three-message
  conversations.
* `function_calling_r2cmd_dataset.jsonl` contains 363 tool-calling conversions.
  Each row has a `messages` array and an `r2cmd` definition in `tools`. Its
  conversation contains system, user, assistant tool call, tool result, and
  final assistant messages.
* `converted_r2cmd_dataset_good_for_mistral.jsonl` contains 3,778 rows in the
  same general function-calling style. It is a legacy prebuilt artifact and is
  not referenced by the current generation scripts.

The classic generation flow is:

```text
radare2_ok.tsv
  -> enrich-dataset.py
  -> radare2_enriched.tsv
  -> prepare-dataset.py
  -> radare2_train.jsonl
  -> r2cmd.py
  -> function_calling_r2cmd_dataset.jsonl
```

### Raw sources

`data/radare2/sources/` contains:

* `all_commands.txt`: 3,186 nonempty command-help lines.
* `fortunes.tips`: 87 radare2 tips.
* `usage.tsv`: 2,855 records plus a header with `main_command`,
  `main_description`, `command`, and `description`.
* `usage_blocks.tsv`: 250 records plus a header with `main_command`,
  `description`, JSON-encoded `commands`, and `raw_text`.
* `usage_batch.jsonl`: 250 OpenAI batch request objects with `custom_id`,
  `method`, `url`, and `body`. This is generation input, not training data.

### Manual review queues

`data/radare2/pending/` contains unreviewed, accepted, ignored, and older
generated proposals:

* Twelve dated `q/a` datasets contain 2,576 proposed pairs: one 2024-10-27
  vulnerability-researcher dataset; ten 2024-10-28 datasets covering binary
  analysis, binary patching, crypto, debugging, exploitation, forensics,
  general use, malware, reverse engineering, and vulnerabilities; and one
  2025-11-03 crypto dataset.
* `commands.tsv` contains 2,142 command/description proposals.
* `every_command_gpt4o.tsv` contains 72,258 generated records with `question`,
  `command`, `r2cmd`, and `explanation`; one row has an irregular column count.
* `every_command_per_block_gpt4o.tsv` contains 10,966 records with `n`,
  `question`, `command`, `r2cmd`, and `explanation`.
* `qwen-fortunes.tsv` contains 94 proposed Q/A rows.
* `claude-numbers2.tsv` contains 21 active category/question/command rows;
  `claude-numbers2.tsv.ok` has 24 accepted rows and
  `claude-numbers2.tsv.ignored` has 101 rejected rows.
* `r2gpt-advent.tsv` contains 219 active rows; `r2gpt-advent.tsv.ok` has 16
  accepted rows and `r2gpt-advent.tsv.ignored` has 67 rejected rows.
* `claude-print.txt`, `claude-search.txt`, `claude-numbers.txt`, `quotes.txt`,
  and `radare2_todo.tsv` are older or loosely structured proposal/prose files.

`review-pending.sh` moves reviewed records into `.ok` or `.ignored` files.
These pending files are not automatically included in training.

### Processed archives

`data/radare2/Attic/` contains historical Q/A inputs:

* `o1-mini.tsv`: 100 rows.
* `o1-preview.tsv`: 100 rows.
* `radare2_train.tsv`: 95 rows.
* `radaregpt.tsv`: 96 rows.

The Attic datasets are not part of the active training merge.

## Verified command companions

### `data/radare2-agentic/`

This dataset verifies direct radare2 command examples against local fixtures.

* `seeds.json`: 10 seed objects with `id`, `kind`, `question`, `answer`,
  `fixture`, optional `setup`, `checks`, `tags`, and `source_refs`.
* `verified.jsonl`: all 10 seeds promoted to training rows.
* `pending-human.jsonl`: currently empty.

A seed is promoted only after its command executes and all declared checks
pass.

### `data/r2js/`

This dataset covers radare2's embedded QuickJS runtime.

* `seeds.json`: 5 objects using the verified seed schema plus a `script` field.
* `verified.jsonl`: 5 verified rows.
* `pending-human.jsonl`: currently empty.

### `data/reasoning-long/`

This dataset contains multi-step reverse-engineering tasks rather than single
command answers.

* `tasks.json`: 4 tasks with `question`, `fixture`, optional `setup`,
  `starter_commands`, checks, a full answer, tags, and source references.
* `verified.jsonl`: 4 training rows.
* `pending-human.jsonl`: currently empty.

## Agentic knowledge

`data/agentic-knowledge/` is the generated, quality-filtered knowledge base:

* `knowledge.jsonl`: 349 deduplicated aggregate rows. It contains 203
  `agentic_knowledge` rows and 146 `agentic_experiment` rows. Of these, 209
  have executable verification metadata and 335 have titles.
* `runs/*.jsonl`: 43 append-only audit shards containing 330 unique rows. Every
  current shard row is represented in the aggregate. Do not train from the
  shards separately.
* `pending-human.jsonl`: currently empty.
* `index.json`: generation statistics, budgets, category limits, and quality
  policies; it is metadata rather than training data.

Major topic families include r2 regression tests, plugins, source
documentation, commands and grammar, r2js, source xrefs, online material,
challenges, decompilation, firmware, forensics, and human-reviewed answers.

The aggregate stores relative source references and is deduplicated by row ID
and content fingerprint. Generic or low-quality rows are filtered during
generation.

## Agentic command grammar

`data/agentic-commands/` describes command families, letters, suffixes,
modifiers, iterators, and command-line composition:

* `commands.jsonl`: 240 source records: 45 `documented`, 185 `needs-memory`,
  and 10 `human-reviewed`.
* `verified.jsonl`: 240 simplified chat-format training exports.
* `memory-topics.jsonl`: 24 clarification topics derived from weak command
  rows.
* `knowledge-memory-topics.jsonl`: 24 clarification topics derived from
  commands found in the broader agentic knowledge base.
* `index.json`: row counts and generation metadata.

A source command record contains `command`, `syntax`, a per-character
`decomposition`, `unknown_parts`, status, messages, sources, tags, topic, and
verification. Human-reviewed rows can also have `memory_refs` and
`memory_resolved_parts`.

## Human memory

`data/memory/` stores corrections and clarifications supplied by humans:

* `topics.jsonl`: 273 clarification topics, currently 266 pending and 7
  answered.
* `memory.jsonl`: 9 accepted source memories.
* `verified.jsonl`: 9 exported chat-format training rows.

A source memory contains a concise `highlight`, detailed explanation, tags,
the original question, source channel, status, timestamps, content fingerprint,
and generated messages. The verified export removes workflow-only fields and
retains the training conversation and provenance.

Rebuild the training export with:

```sh
make memory-export
```

## Agentic human review

`data/agentic-review/` is an audit and human-review queue:

* `questions.tsv`: 3 curated pending questions. Its columns are `dataset`,
  `id`, `kind`, `question`, `proposed_answer`, `fixture`, `reason`, `status`,
  and `source_refs`.
* `generated-failures.tsv`: currently header-only.
* `human-responses.jsonl`: 3 review records containing the action, human
  answer, original pending object, timestamps, and source queue.

## ESIL examples

`data/esil/` contains instruction-to-ESIL examples:

* `esil_arm.tsv`: 35 headerless rows with assembly, ESIL, pseudocode, and an
  explanation.
* `esil_x86.tsv`: 2 headerless rows with the same basic fields plus an empty
  fifth column.

These files are not included in the current training merge.

## r2frida data

`data/r2frida/` contains:

* `r2frida_ok.tsv`: 12 headerless question/command pairs.
* `pending/claude.txt`, `pending/claude2.txt`, `pending/o1-preview.txt`, and
  `pending/r2gpt.txt`: four loosely structured generated or prose sources.

The r2frida data is not included in the current training merge.

## Merged training output

`data/training/radare2_all_agentic_train.jsonl` is the assembled, uniform chat
dataset. Each row contains only `messages`. It is generated from the seven
active sources listed at the top of this document and should not be edited
manually.

## Files that are not datasets

The following repository artifacts must not be treated as training data:

* `R2BUGS.md`: generated bug leads. A lead belongs in training only after
  manual confirmation and conversion into a reviewed row.
* `index.json` files: generation statistics and state.
* Dataset `README.md` files and files under `doc/`: documentation.
* `dataset-gen-prompt.txt`: a generation prompt.
* Scripts under dataset directories: dataset generators.
* Jupyter notebooks, virtual environments, training checkpoints, model
  weights, and GGUF files.
