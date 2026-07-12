# r2ai-model CLI

`r2ai-model` is the primary interface for preparing data, reviewing generated
questions, fine-tuning, and using a model. It resolves its checkout through the
installed symlink, so it works from any directory.

```sh
r2ai-model help
r2ai-model help refresh-commands
r2ai-model status
```

## Mental model

```text
source datasets
  classic TSV/JSONL   command knowledge   agentic knowledge   human memory
          |                   |                   |                 |
          +-------------------+-------------------+-----------------+
                                      |
                                    merge
                                      |
             data/training/radare2_all_agentic_train.jsonl
                                      |
                    preflight (optional) or train
                                      |
                         final model + exported GGUF
                                      |
                              chat or serve
```

Three commands change source datasets:

- `refresh-commands` reads installed radare2 help and rebuilds the command
  training source. The old name `commands` remains as an alias.
- `learn` discovers and verifies broader radare2 knowledge.
- `review` records human answers and corrections.

They do not fine-tune. `merge` combines the current sources, while `train`
already compiles and merges before fine-tuning.

| Command | Grows knowledge/review data | Builds merged JSONL | Loads model weights |
| --- | --- | --- | --- |
| `datasets`, `status` | No | No | No |
| `refresh-commands`, `learn`, `review` | Yes | No | No |
| `merge` | No | Yes | No |
| `preflight` | No | Yes | No |
| `train` | No | Yes | Yes |
| `chat`, `serve` | No | No | Yes |

## Which workflow should I run?

Fine-tune from the sources already in the checkout:

```sh
r2ai-model train --preset qwen
```

That single command installs dependencies, compiles classic sources, exports
accepted memory, merges all sources, fine-tunes, merges LoRA, and exports GGUF.
A separate `merge` or `preflight` is not required.

For a safer expensive run, validate first:

```sh
r2ai-model preflight --preset qwen
r2ai-model train --preset qwen
```

Preflight repeats compilation and merge, but does not load model weights. Use
`merge` alone only when you want to inspect or distribute the combined JSONL
without training:

```sh
r2ai-model merge
r2ai-model datasets --check
```

Refresh command knowledge before training only when radare2 help changed or you
want to regenerate that curriculum:

```sh
r2ai-model refresh-commands --ai off --no-queue-memory
r2ai-model preflight --preset qwen
r2ai-model train --preset qwen
```

## Dataset sources

```sh
r2ai-model datasets
r2ai-model datasets --check
r2ai-model datasets --format json
```

`datasets` is the read-only inventory. `--check` exits nonzero when an input is
missing or newer than the merged dataset.

`refresh-commands` is not a listing command. It reads `?*` and focused help,
checks executable workflows, and writes `data/agentic-commands/*.jsonl`:

```sh
r2ai-model refresh-commands
r2ai-model refresh-commands --memory-limit 0 --no-queue-memory
r2ai-model learn --online off
r2ai-model verify --verbose
```

Generated clarification topics are queued for review by default. Use
`--no-queue-memory` to keep them out of the shared queue, and
`--memory-limit 0` to disable their generation.

## Review

`review` selects the first non-empty queue: agentic checks, human-memory
questions, then the legacy TSV. Select one explicitly when desired:

```sh
r2ai-model review
r2ai-model review memory --list
r2ai-model review agentic --list
r2ai-model review legacy --file data/radare2/pending/example.tsv
```

Batch agents can use the JSON memory protocol:

```sh
r2ai-model next --format json > question.json
r2ai-model answer < answer.json
r2ai-model export
```

## Presets, chat, and serving

| Preset | Configuration |
| --- | --- |
| `qwen` | `training/config.yaml` |
| `minicpm5` | `training/config.minicpm5.yaml` |
| `lfm25` | `training/config.lfm2.5.yaml` |

```sh
r2ai-model train --preset minicpm5
r2ai-model train --config custom.yaml
r2ai-model chat --preset qwen
r2ai-model chat --preset qwen --backend llama.cpp
r2ai-model serve --preset qwen --host 127.0.0.1 --port 8080
```

`status` compares the merged dataset hash with each preset's training metadata
and reports `ready`, `export`, or `retrain`, along with the expected GGUF path.

## Advanced and compatibility commands

- `compile` rebuilds only the legacy chat and tool-call sources. `merge`,
  `preflight`, and `train` already call it.
- `build` exposes fixed companion-dataset verification.
- `propose` creates quarantined AI proposals; it does not promote them.
- `clean --dry-run` previews removable training artifacts.
- Arguments after `--` are forwarded for underlying options added later.
- `make` remains a compatibility escape hatch.

```sh
r2ai-model help <command>
r2ai-model make help
r2ai-model make -- -C training help
```
