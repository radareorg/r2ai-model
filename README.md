# r2ai-model

Datasets and local fine-tuning tools for teaching language models to use
radare2 accurately. The repository combines classic command examples,
function-calling rows, verified workflows, generated command knowledge,
source-grounded agentic knowledge, and human corrections.

## Quick start

Install a symlink to the checkout:

```sh
sudo make install
r2ai-model status
```

Fine-tune the default Qwen preset from the datasets already present:

```sh
r2ai-model train --preset qwen
```

`train` is self-contained: it installs dependencies, compiles classic sources,
exports accepted memory, merges all training sources, fine-tunes, merges LoRA,
and exports GGUF. A separate `merge` or `preflight` is not required.

For an inexpensive safety check before a long run:

```sh
r2ai-model preflight --preset qwen
r2ai-model train --preset qwen
```

Use the result through Ollama or llama.cpp:

```sh
r2ai-model chat --preset qwen
r2ai-model serve --preset qwen --port 8080
```

## How data moves

```text
classic + commands + agentic knowledge + human memory
                         |
                       merge
                         |
                 merged training JSONL
                         |
                  preflight or train
                         |
                 final model and GGUF
```

`refresh-commands`, `learn`, and `review` update source datasets. They do not
merge or fine-tune. `datasets` and `status` are read-only. `train` always
compiles and merges first.

```sh
# Read-only inventory
r2ai-model datasets
r2ai-model status

# Optional source-dataset growth
r2ai-model refresh-commands --ai off --no-queue-memory
r2ai-model learn
r2ai-model review

# Optional standalone merge or validation
r2ai-model merge
r2ai-model preflight --preset qwen

# Fine-tuning
r2ai-model train --preset qwen
```

`r2ai-model commands` remains an alias for `refresh-commands`; despite the old
name, it rebuilds command training data rather than listing commands.

## Human and agent review

```sh
r2ai-model review
r2ai-model review memory --list
r2ai-model next --format json > question.json
r2ai-model answer < answer.json
```

Accepted corrections are stored in `data/memory/memory.jsonl` and exported to
`data/memory/verified.jsonl`, which participates in the next merge or training
run.

## Documentation

- [CLI and machinery](doc/cli.md): lifecycle, command effects, and recipes.
- [Datasets](doc/datasets.md): schemas, inventories, trust gates, and merge inputs.
- [Command curriculum](doc/commands.md): radare2 help and verified workflows.
- [Learning](doc/learn.md): agentic knowledge discovery and audit shards.
- [Review](doc/review.md): verification and pending human decisions.
- [Memory](doc/memory.md): corrections and the batch-agent JSON protocol.
- [Training](doc/train.md): model configs, masking, splitting, and export.
- [Make targets](doc/make.md): lower-level automation and compatibility.
- [Bug leads](doc/bugs.md): why unconfirmed `R2BUGS.md` entries stay out of training.
- [AGENTS.md](AGENTS.md): concise operational rules for repository agents.

Run `r2ai-model help` or `r2ai-model help <command>` for live CLI help. Make
targets remain available through `make help` and `make -C training help`.

## Data policy

- Train from aggregate `verified.jsonl` and `knowledge.jsonl` files, not every
  audit shard independently.
- Keep failed or unresolved checks in pending queues.
- Keep generated bug leads out of training until manually confirmed and
  converted into reviewed rows.
- Do not commit virtual environments, merged training artifacts, model output
  directories, or GGUF files.
