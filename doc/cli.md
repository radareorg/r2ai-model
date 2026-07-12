# r2ai-model CLI

`r2ai-model` is the preferred interface for dataset preparation, review,
training, and inference. It resolves its source checkout even when invoked
through the installed symlink, so commands can be run from any directory.

```sh
r2ai-model help
r2ai-model help commands
r2ai-model status
```

## Dataset lifecycle

Inspect source counts and whether the merged dataset is current:

```sh
r2ai-model datasets
r2ai-model datasets --check
r2ai-model datasets --format json
```

`--check` exits nonzero when an input is missing or newer than the merged
dataset. Refresh individual sources, then merge them:

```sh
r2ai-model commands
r2ai-model commands --ai off --no-queue-memory
r2ai-model learn
r2ai-model verify
r2ai-model compile
r2ai-model merge
```

The command builders expose their useful options directly. The `--` escape
hatch remains available for new underlying options not yet represented by the
wrapper:

```sh
r2ai-model help commands
r2ai-model commands --memory-limit 0 --no-queue-memory
r2ai-model build --dataset r2cmd
r2ai-model verify --id knowledge.example --verbose
r2ai-model commands -- --future-option value
```

## Review

`review` chooses the first non-empty queue in this order: agentic pending rows,
human-memory questions, then the legacy TSV. A queue can also be selected
explicitly.

```sh
r2ai-model review
r2ai-model review memory --list
r2ai-model review agentic --list
r2ai-model review legacy --file data/radare2/pending/example.tsv
```

The memory protocol supports both humans and batch agents:

```sh
r2ai-model play
r2ai-model next --format json > question.json
r2ai-model answer < answer.json
r2ai-model queue "ESIL stepping" --question "How does aesue stop?" --tags radare2,esil
r2ai-model export
```

## Training

Use a named preset or a configuration path. `preflight` and `train` always
compile and merge the active datasets first.

```sh
r2ai-model preflight --preset qwen
r2ai-model train --preset qwen
r2ai-model train --preset minicpm5
r2ai-model train --preset lfm25
r2ai-model train --config custom.yaml
```

Preset mapping:

| Preset | Configuration |
| --- | --- |
| `qwen` | `training/config.yaml` |
| `minicpm5` | `training/config.minicpm5.yaml` |
| `lfm25` | `training/config.lfm2.5.yaml` |

`r2ai-model status` compares the merged dataset hash with each preset's
training metadata and reports `ready`, `export`, or `retrain`. It also prints
the expected GGUF path.

## Chat and serving

Use a preset to select its standard GGUF, or pass an explicit model path:

```sh
r2ai-model chat --preset qwen
r2ai-model chat --model custom.gguf --name r2ai-custom --context 8192
r2ai-model chat --preset qwen --create-only
r2ai-model chat --preset qwen --backend llama.cpp
r2ai-model chat --model custom.gguf --backend llama.cpp --llama-cli /path/to/llama-cli
r2ai-model serve --preset qwen --host 127.0.0.1 --port 8080
r2ai-model serve --model custom.gguf --llama-args --jinja --metrics
```

Advanced server overrides are available through `--server`, `--library-path`,
and `--llama-args`.

## Maintenance and compatibility

```sh
r2ai-model clean --dry-run
r2ai-model clean
sudo r2ai-model make install
sudo r2ai-model make uninstall
```

The Make bridge remains for uncommon or newly added targets, but ordinary
workflows should not need it:

```sh
r2ai-model make help
r2ai-model make -- -C training help
```
