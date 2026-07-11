# Agent Commands

Basic workflow for this repository:

```sh
# install the agent-facing CLI into /usr/local/bin
make install
r2ai-model status

# discover/register new agentic knowledge
make agentic
r2ai-model learn

# verify registered executable knowledge
make agentic-verify
r2ai-model verify

# build command grammar rows and queue command-memory questions
make agentic-commands
r2ai-model commands

# answer or drop pending human-review rows
make agentic-pending
r2ai-model pending

# collect human corrections interactively or through JSON batch mode
make memory
make agentic-memory
make agentic-memory-file < answer.json
r2ai-model play
r2ai-model next --format json
r2ai-model answer < answer.json
make memory-export

# validate templates, then install deps, merge all data, train, and export GGUF
make preflight
make train
r2ai-model preflight
r2ai-model train

# train MiniCPM5 against the merged agentic dataset
make -C training train-minicpm5

# chat with the default trained GGUF through Ollama
make chat
r2ai-model chat

# serve a trained GGUF through llama.cpp
make serve
r2ai-model serve
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
