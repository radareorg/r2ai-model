# Agentic radare2 command dataset

This directory contains a non-interactive companion to the manual TSV review
flow. Seed rows in `seeds.json` are verified by `../../agentic-dataset.py`
against the local radare2 source tree and test binaries.

Generated files:

- `verified.jsonl`: training-ready chat rows with command evidence.
- `pending-human.jsonl`: rows that failed verification and need a human.

Each seed should include explicit checks. A row is only promoted when radare2
runs the command and the output satisfies those checks.
