# Training

Build one training JSONL from the classic dataset, verified companion datasets,
and the agentic knowledge aggregate:

```sh
make agentic-verify

mkdir -p data/training
cat \
  data/radare2/radare2_train.jsonl \
  data/radare2-agentic/verified.jsonl \
  data/r2js/verified.jsonl \
  data/reasoning-long/verified.jsonl \
  data/agentic-knowledge/knowledge.jsonl \
  > data/training/radare2_all_agentic_train.jsonl
```

Point `training/config.yaml` at the merged dataset:

```yaml
dataset:
  path: "../data/training/radare2_all_agentic_train.jsonl"
```

Choose the model in the same file:

```yaml
model:
  name: "Qwen/Qwen2.5-3B-Instruct"
  tokenizer: null
```

Use a small model for pipeline testing and a larger model for real training:

```yaml
# smoke test
name: "HuggingFaceTB/SmolLM-135M"

# local training
name: "Qwen/Qwen2.5-1.5B-Instruct"
name: "Qwen/Qwen2.5-3B-Instruct"

# current heavier default
name: "jan-hq/Qwen3-4B-no-think"
```

For larger models, enable LoRA:

```yaml
lora:
  use_lora: true
```

Run training:

```sh
make -C training train
```

Run the full setup, dependency install, dataset compilation, and training target:

```sh
make -C training
```
