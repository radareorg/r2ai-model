# Agent Commands

Basic workflow for this repository:

```sh
# discover/register new agentic knowledge
make agentic

# verify registered executable knowledge
make agentic-verify

# answer or drop pending human-review rows
make agentic-pending

# merge all training-ready datasets
mkdir -p data/training
cat \
  data/radare2/radare2_train.jsonl \
  data/radare2-agentic/verified.jsonl \
  data/r2js/verified.jsonl \
  data/reasoning-long/verified.jsonl \
  data/agentic-knowledge/knowledge.jsonl \
  > data/training/radare2_all_agentic_train.jsonl

# train with training/config.yaml
make -C training train
```

Before training, set `training/config.yaml`:

```yaml
dataset:
  path: "../data/training/radare2_all_agentic_train.jsonl"
model:
  name: "Qwen/Qwen2.5-3B-Instruct"
  tokenizer: null
```

Keep generated bug leads in `R2BUGS.md` out of training data unless they are
manually confirmed and converted into a reviewed training row.
