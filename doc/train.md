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
