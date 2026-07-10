# Agent Commands

Basic workflow for this repository:

```sh
# discover/register new agentic knowledge
make agentic

# verify registered executable knowledge
make agentic-verify

# build command grammar rows and queue command-memory questions
make agentic-commands

# answer or drop pending human-review rows
make agentic-pending

# collect human corrections interactively or through JSON batch mode
make memory
make agentic-memory
make agentic-memory-file < answer.json
make memory-export

# merge all training-ready datasets
make -C training merge-agentic-dataset

# train with training/config.yaml against the merged agentic dataset
make -C training train-agentic CONFIG=config.yaml

# train MiniCPM5 against the merged agentic dataset
make -C training train-minicpm5

# chat with a trained GGUF through Ollama
make -C training chat MODEL=radare2-smollm-finetuned.gguf

# serve a trained GGUF through llama.cpp
make -C training serve MODEL=radare2-qwen3-4b-finetuned.gguf
```

Before custom training, set the config:

```yaml
dataset:
  path: "../data/training/radare2_all_agentic_train.jsonl"
model:
  name: "Qwen/Qwen2.5-3B-Instruct"
  tokenizer: null
```

Keep generated bug leads in `R2BUGS.md` out of training data unless they are
manually confirmed and converted into a reviewed training row.

Human corrections collected with `make memory` are stored in
`data/memory/memory.jsonl` and exported to `data/memory/verified.jsonl`. The
agentic training merge includes that export.
