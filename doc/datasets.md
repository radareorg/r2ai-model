# Datasets

This repository currently has two parallel dataset systems:

1. A legacy/manual TSV pipeline for collecting and reviewing question/command
   pairs.
2. A verified agentic JSONL pipeline for executable examples, source-grounded
   knowledge, command grammar, long-form reasoning, and human corrections.

The inventory below describes the current worktree. Generated row counts may
change after running the agentic, memory, review, or merge commands.

## Active training datasets

The default training workflow merges these eight files:

| Dataset | Rows | Review or evidence gate |
| --- | ---: | --- |
| `data/radare2/function_calling_r2cmd_dataset.jsonl` | 363 | Deterministic conversion of the classic accepted commands; not separately executed |
| `data/radare2/radare2_train.jsonl` | 363 | Compiled from the legacy accepted TSV; malformed rows are skipped |
| `data/radare2-agentic/verified.jsonl` | 10 | Command execution and declared checks pass on local fixtures |
| `data/r2js/verified.jsonl` | 5 | Local r2js execution and checks pass |
| `data/reasoning-long/verified.jsonl` | 4 | Local multi-command execution and checks pass |
| `data/agentic-knowledge/knowledge.jsonl` | 357 | Mixed executable, source-scan checked, and source-grounded knowledge |
| `data/agentic-commands/verified.jsonl` | 3,057 | Exact current `?*` help: 1,961 trusted individual rows, 364 scoped family chunks, 294 intent-selection rows, 402 focused command lessons, and 36 verified workflow variants |
| `data/memory/verified.jsonl` | 9 | Direct human corrections exported from accepted memory records |
| **Current source total** | **4,168** | Expected result of a fresh merge |

The merge validates every conversation and writes a uniform training-only row
containing `messages` and optional `tools`. It does not shuffle, split, or
deduplicate across the eight sources. Rebuild it with:

```sh
make -C training merge-agentic-dataset
```

Source identifiers, provenance, and verification details remain in the source
datasets. They are intentionally omitted from the merged artifact because the
training loader consumes only `messages` and optional `tools`, and
heterogeneous verification check values cannot be represented by one inferred
Arrow schema.

The current generated artifact contains all 4,168 rows from the eight sources.
The active training configs use a 2,048-token limit, which contains the current
longest row (1,836 tokens with the local Qwen chat template) without truncation.
Batch padding remains dynamic, so shorter command examples retain their natural
length until collation.
At preprocessing time, the selected tokenizer's native chat template renders
model-specific role markers, separators, tool calls, and end-of-turn tokens.
The rendered text is tokenized with `add_special_tokens=False` so special tokens
are not duplicated and offset mappings remain available for loss masking.
Training labels use `-100` outside assistant response spans. System prompts,
user questions, and model-specific assistant prompt markers remain in
`input_ids` as context but do not contribute directly to the loss.
Function-calling rows also retain top-level tool definitions, assistant
`tool_calls`, and structured argument objects. They intentionally stop after
the assistant tool call: the classic source has no real r2 execution output, so
the old command-echo "result" is no longer fabricated as training data.

There is no persistent split artifact. Training creates a deterministic,
group-aware test split using `dataset.test_split` and `dataset.split_seed`.
Rows sharing a normalized user question, exact assistant target, or canonical
tool call are connected and assigned together, preventing command variants and
their tool-calling equivalents from leaking across train and test.
The current split is 3,325 train rows and 370 test rows across 2,711 related-row
groups. There are 623 normalized duplicate user-question groups covering 1,583
rows, including deliberate classic text-answer/tool-call pairs and related
command variants. They are kept in the same split, but their duplicated weight
should be evaluated by ablation.

All included configs point to the merged dataset. `training/config.yaml` is the
default Qwen3 4B LoRA run; `training/config.minicpm5.yaml` and
`training/config.lfm2.5.yaml` provide smaller non-Qwen alternatives.

## Creation, maintenance, and review lifecycle

The repository does not have one uniform definition of "verified." The actual
promotion paths are:

| Source family | Created by | Machine review | Human review | Enters training when |
| --- | --- | --- | --- | --- |
| Classic TSV | Historical/manual and LLM-assisted TSV generation | Shape checks in `prepare-dataset.py` only | Accepted rows live in `radare2_ok.tsv`; pending files use `review-pending.sh` | It compiles to a valid Q/A row |
| Classic tool calls | `r2cmd.py` converts each classic command | Deterministic schema conversion; no r2 execution | Inherits classic acceptance | Tool name and structured command argument are valid |
| Fixed agentic seeds | Humans author `seeds.json` or `tasks.json` | radare2/r2js runs locally and every declared check passes | Failures may enter `pending-human.jsonl` | Verification succeeds |
| Agentic knowledge | Deterministic source/doc/test scanners, experiments, optional online collection, and accepted human answers | ID/content dedupe, quality filters, category caps; executable rows run checks | Pending answers are recorded in `human-responses.jsonl` | The builder promotes it to the aggregate; not every row has executable evidence |
| Command grammar | Current local `?*`, scoped help parsing, prefix relationships, and checked knowledge workflows | Full-help anti-truncation gate, exact evidence, unique IDs, role validation, and successful help checks | Memory answers can replace thin descriptions | Status is `documented` or `human-reviewed`; 39 `needs-memory` rows are withheld |
| Human memory | A person answers a queued topic or records a correction | JSON/schema, fingerprint, and duplicate handling; no factual verifier | The submitter is the review authority | Memory status is accepted and `memory.py export-training` runs |
| AI proposals | `agentic-dataset.py propose` calls an OpenAI-compatible model | JSON parsing only | None in the proposal command itself | Never automatically; `ai-proposals.jsonl` is currently disconnected from promotion |

`make agentic` is primarily deterministic and local. Optional AI is used to
draft proposal rows or better questions for humans; those outputs are not a
trusted answer source by themselves. The legacy `generate-dataset.py` and
`enrich-dataset.py` paths can call external models, but the normal compile target
does not invoke them: it rebuilds from the existing accepted/enriched files.

The agentic knowledge aggregate currently contains 203 rows with successful
executable checks, 6 with `source-scan-ok`, and 140 without machine-verification
metadata. Two aggregate rows are tagged `human-review`. The 9 human-memory rows
are a separate, explicitly human-authored source. This distinction matters:
valid JSON and provenance are not the same as factual or executable validation.

Current human-review state is 314 pending memory topics and 7 answered topics,
plus the curated agentic review queues. The command builder reduced its withheld
set from 185 of 240 rows to 39 of 1,971 rows by trusting exact help behavior
without guessing unresolved letter meanings.

## Training and model compatibility

The public workflows are:

```sh
make train
make chat

# The installed/source CLI exposes the same operations.
r2ai-model train
r2ai-model chat
```

`make train` and `r2ai-model train` create/update the venv, repair compatible
dependencies, rebuild classic and tool-call rows, export human memory, merge all
training-ready sources, train with LoRA by default, merge the adapter into a
complete model, and export GGUF. `make chat` and `r2ai-model chat` import the
default GGUF into Ollama and start the session. The default chat filename now
matches the default Qwen config output.

Before downloading model weights or starting an expensive run, validate a
config's tokenizer and every dataset row:

```sh
r2ai-model preflight
r2ai-model preflight --config config.minicpm5.yaml
r2ai-model preflight --config config.lfm2.5.yaml
```

The current 4,168-row corpus passes full preflight with the default Qwen config;
run the same preflight after changing either alternative model dependency set.
The included model configurations are:

| Config | Model | Parameters | Full template preflight | Intended strength |
| --- | --- | ---: | --- | --- |
| `config.yaml` | `jan-hq/Qwen3-4B-no-think` | 4B | Pass | Heavier default |
| `config.minicpm5.yaml` | `openbmb/MiniCPM5-1B` | 1B | Not rerun | Small tool use, code, reasoning |
| `config.lfm2.5.yaml` | `LiquidAI/LFM2.5-1.2B-Instruct` | 1.2B | Not rerun | Fast edge inference and function calling |

Passing preflight means the fast tokenizer, chat template, structured tool
calls, assistant-only labels, maximum length, and split all work. It does not
prove that a completed fine-tune is accurate. No full training run or held-out
executable model benchmark was completed as part of this audit, and the project
currently has no such benchmark; model quality is therefore unknown rather than
"good."

A new model is suitable only if it is an instruct/chat causal LM with a fast
tokenizer, a stable append-only chat template, and native `tools`/`tool_calls`
support for the full dataset. Base models such as GPT-2 or base SmolLM do not
meet that contract without supplying a template, and a chat model that ignores
tools is unsuitable for the r2 agent objective. Run preflight for every model
change. LoRA uses PEFT's `all-linear` target selection to avoid Qwen-specific
module names.

The reported `HybridCache` import failure came from `peft 0.17.1` with
`transformers 5.13.1`. Requirements now enforce `peft>=0.18,<1` and
`transformers>=5.6,<6`, so the normal requirements install upgrades stale PEFT
without requesting a blanket upgrade of an otherwise valid PyTorch/CUDA stack.
The repaired environment imports `peft 0.19.1` with `transformers 5.13.1`.

## Improvements still needed

In priority order:

1. Build a frozen executable evaluation set that is never merged into training.
   Score exact/normalized command selection, tool-call JSON, command execution,
   expected output checks, refusal on unsafe/unknown requests, and multi-turn
   recovery. The current grouped 10% split measures loss, not useful r2 ability.
2. Work down the human backlog, starting with the 39 withheld command rows and
   common workflow gaps. Each accepted correction should rebuild `commands.jsonl`, its
   trusted export,
   trusted export, and the merged dataset.
3. Add an explicit trust policy for the 140 agentic-knowledge rows without
   machine checks and the legacy 363 Q/A pairs. Require a human approval marker,
   a source assertion check, or an executable fixture before high-weight use.
4. Connect AI proposals to a verifier-and-human-review import command, or keep
   them clearly quarantined. Never merge raw `ai-proposals.jsonl` directly.
5. Add real fixture-backed multi-turn tool traces: assistant call, actual r2
   output as a masked tool message, and a grounded final answer. The current
   tool rows correctly teach selection only.
6. Add a versioned manifest with source hashes, row counts, trust tiers, build
   command, tokenizer, and split seed. This makes model/data provenance
   reproducible instead of relying on mutable generated paths.
7. Compare source weighting and ablations. The paired 363 classic text and 363
   tool-call rows dominate the corpus and may suppress the smaller, higher-trust
   sources. Report results per dataset family, not only aggregate eval loss.
8. Record full-run metrics and resource use for Qwen, MiniCPM5, and LFM2.5,
   including base-vs-fine-tuned executable scores and GGUF/Ollama smoke tests.

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
* `function_calling_r2cmd_dataset.jsonl` contains 363 tool-calling conversions
  and is included in the active merge. Each row has a `messages` array and an
  `r2cmd` definition in `tools`. Its conversation contains system, user, and a
  final assistant tool call with object-form arguments. Stable call IDs are
  derived from the question and command, and source ordering is deterministic.
  No fake tool result or final answer is generated.
* `converted_r2cmd_dataset_good_for_mistral.jsonl` contains 3,778 rows in the
  same general function-calling style. It remains a legacy prebuilt artifact
  outside the active merge, but the training loader now supports its structure
  when selected explicitly.

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

* `knowledge.jsonl`: 357 deduplicated aggregate rows. It contains 207
  `agentic_knowledge` rows and 150 `agentic_experiment` rows. Of these, 211
  have successful executable verification, 6 have source-scan checks, 140 have
  no machine-verification status, and 343 have titles.
* `runs/*.jsonl`: append-only audit shards. Do not train from the shards
  separately.
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

* `commands.jsonl`: 1,971 source records: 1,922 `documented`, 39
  `needs-memory`, and 10 `human-reviewed`; 134 link to executable workflows.
* `families.jsonl`: 360 scoped chunks from 257 `Usage:` help blocks. Local
  legends and mode keys remain context-local instead of becoming fake commands.
* `selection.jsonl`: 292 balanced task-to-command rows, using one family
  representative plus commands found in executable workflows.
* `verified.jsonl`: 2,584 simplified chat-format training exports. The 39
  `needs-memory` records remain withheld from training.
* `memory-topics.jsonl`: 24 clarification topics derived from weak command
  rows.
* `knowledge-memory-topics.jsonl`: 24 clarification topics derived from
  commands found in the broader agentic knowledge base.
* `index.json`: row counts, current help hash, quality-gate results, and
  workflow-link statistics.

A source command record contains `command`, `syntax`, a per-character
`decomposition`, `unknown_parts`, status, messages, sources, tags, topic, and
verification. Human-reviewed rows can also have `memory_refs` and
`memory_resolved_parts`.

## Human memory

`data/memory/` stores corrections and clarifications supplied by humans:

* `topics.jsonl`: 321 clarification topics, currently 314 pending and 7
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
* `ai-proposals.jsonl`, when generated, is raw AI proposal storage only. The
  current `propose` command does not verify, queue, or promote these rows.

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
dataset. Each row contains `messages` and a `tools` list, which is empty for
ordinary chat rows. It is generated from the eight active sources listed at the
top of this document and should not be edited manually.

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
