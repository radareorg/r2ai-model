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
make -C training merge-agentic-dataset

# train with training/config.yaml against the merged agentic dataset
make -C training train-agentic CONFIG=config.yaml

# train MiniCPM5 against the merged agentic dataset
make -C training train-minicpm5
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
