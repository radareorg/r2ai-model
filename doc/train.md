# Training

Build one training JSONL from the classic dataset, verified companion datasets,
and the agentic knowledge aggregate:

```sh
make agentic-verify
make -C training merge-agentic-dataset
```

The merge target writes:

```text
data/training/radare2_all_agentic_train.jsonl
```

Equivalent manual merge:

```sh
mkdir -p data/training
cat \
  data/radare2/radare2_train.jsonl \
  data/radare2-agentic/verified.jsonl \
  data/r2js/verified.jsonl \
  data/reasoning-long/verified.jsonl \
  data/agentic-knowledge/knowledge.jsonl \
  > data/training/radare2_all_agentic_train.jsonl
```

Choose the model in a training config:

```yaml
model:
  name: "Qwen/Qwen2.5-3B-Instruct"
  tokenizer: null

dataset:
  path: "../data/training/radare2_all_agentic_train.jsonl"
```

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
