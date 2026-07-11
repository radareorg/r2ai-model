# Training

Build one training JSONL from the classic dataset, verified companion datasets,
the agentic knowledge aggregate, and exported human memory rows:

```sh
make agentic-verify
make agentic-commands
make memory-export
make -C training merge-agentic-dataset
```

The merge target writes:

```text
data/training/radare2_all_agentic_train.jsonl
```

Equivalent manual merge:

```sh
mkdir -p data/training
python3 training/merge_datasets.py \
  --output data/training/radare2_all_agentic_train.jsonl \
  data/radare2/function_calling_r2cmd_dataset.jsonl \
  data/radare2/radare2_train.jsonl \
  data/radare2-agentic/verified.jsonl \
  data/r2js/verified.jsonl \
  data/reasoning-long/verified.jsonl \
  data/agentic-knowledge/knowledge.jsonl \
  data/agentic-commands/verified.jsonl \
  data/memory/verified.jsonl
```

The merger validates each conversation and writes the uniform `messages` and
`tools` fields used by training. Source metadata remains in the individual
datasets.

Choose the model in a training config:

```yaml
model:
  name: "Qwen/Qwen2.5-3B-Instruct"
  tokenizer: null

dataset:
  path: "../data/training/radare2_all_agentic_train.jsonl"
  max_length: 2048
```

`max_length` defaults to 2048 tokens. Tokenized rows keep their natural
length and are padded dynamically by the batch collator, so short examples do
not pay the memory cost of the longest sequence in the full dataset.
Conversations are rendered with the selected tokenizer's native chat template;
the tokenizer must therefore provide `chat_template` metadata.
Labels are masked to `-100` for system, user, and assistant-prompt tokens, so
loss is computed only on assistant response bodies and their end-of-turn tokens.
Function-calling rows pass their `tools` definitions to the same native chat
template. Assistant tool calls and final assistant responses are supervised;
`tool` result messages remain masked context.

Useful model choices:

```yaml
# smoke test
name: "HuggingFaceTB/SmolLM-135M"

# small local instruct models
name: "Qwen/Qwen2.5-1.5B-Instruct"
name: "Qwen/Qwen2.5-3B-Instruct"

# small fast tool-calling model
name: "openbmb/MiniCPM5-1B"

# current heavier default
name: "jan-hq/Qwen3-4B-no-think"
```

For larger models, enable LoRA:

```yaml
lora:
  use_lora: true
```

Train with the selected config:

```sh
make -C training train-agentic CONFIG=config.yaml
```

Train MiniCPM5 with the included config:

```sh
make -C training train-minicpm5
```

MiniCPM5 uses the standard Llama causal-LM architecture, but its model card recommends `transformers>=5.6`. The training requirements reflect that floor.

## Chat Or Serve

Use the default small GGUF with Ollama:

```sh
make -C training chat
```

Use a specific GGUF from disk:

```sh
make -C training chat MODEL=radare2-qwen3-4b-finetuned.gguf OLLAMA_MODEL=r2ai-qwen3
```

Serve the same file with llama.cpp's OpenAI-compatible server:

```sh
make -C training serve MODEL=radare2-qwen3-4b-finetuned.gguf LLAMA_PORT=8080
```

Then point an OpenAI-compatible client at `http://127.0.0.1:8080/v1`.
