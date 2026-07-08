# Agentic review queue

This directory is only for the agentic dataset pipeline.

- `questions.tsv` contains curated questions for humans about policy or
  ambiguous examples.
- `generated-failures.tsv` is overwritten by `agentic-dataset.py build` with
  rows that failed local verification.
- `ai-proposals.jsonl` and `ai-proposals-raw.txt` are optional outputs from
  `agentic-dataset.py propose`.

The manual TSV review flow under `data/radare2/pending/` is not read from or
written to by the agentic pipeline.
