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
  test_split: 0.1
  split_seed: 42
  max_length: 2048
```

`test_split` is group-aware and deterministic. Rows sharing a normalized user
question, assistant target, or canonical tool call remain together, so command
variants and their tool-calling equivalents cannot leak across train and test.
`split_seed` controls the stable assignment of complete groups.

`max_length` defaults to 2048 tokens. Tokenized rows keep their natural
length and are padded dynamically by the batch collator, so short examples do
not pay the memory cost of the longest sequence in the full dataset.
Conversations are rendered with the selected tokenizer's native chat template;
the tokenizer must therefore provide `chat_template` metadata.
Labels are masked to `-100` for system, user, and assistant-prompt tokens, so
loss is computed only on assistant response bodies and their end-of-turn tokens.
Function-calling rows pass their `tools` definitions to the same native chat
template. The current classic tool rows supervise the assistant's `r2cmd` call
and structured arguments, then stop because no real tool output exists.

Useful model choices:

```yaml
# included small tool-capable configs
name: "openbmb/MiniCPM5-1B"
name: "LiquidAI/LFM2.5-1.2B-Instruct"

# current heavier default
name: "jan-hq/Qwen3-4B-no-think"
```

The included configs use LoRA with portable `all-linear` target selection:

```yaml
lora:
  use_lora: true
```

Validate all rows against a model template without loading weights:

```sh
r2ai-model preflight
r2ai-model preflight --config config.minicpm5.yaml
```

Train the default model, including dependency setup, merge, and GGUF export:

```sh
make train
r2ai-model train
```

Alternative included configs:

```sh
make -C training train-minicpm5
make -C training train-lfm25
```

MiniCPM5 uses the standard Llama causal-LM architecture, but its model card recommends `transformers>=5.6`. The training requirements reflect that floor.

## Chat Or Serve

Use the default GGUF with Ollama:

```sh
make chat
r2ai-model chat
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
