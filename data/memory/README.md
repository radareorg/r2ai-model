# Human Memory

This directory stores human corrections and clarifications collected by
`make memory`. The source of truth is `memory.jsonl`; `verified.jsonl` is the
generated training export.

Schema highlights:

* `topics.jsonl`: pending, answered, or dropped clarification prompts.
* `memory.jsonl`: accepted memories with `highlight`, `details`, `tags`,
  `source.channel`, `content_fingerprint`, and chat `messages`.
* `verified.jsonl`: chat rows generated from accepted memories for the training
  merge.

Use `./memory.py export-training` to rebuild `verified.jsonl` from source
memories.
