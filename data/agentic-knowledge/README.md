# Agentic Knowledge Base

`make agentic` grows this directory. It does not replace the manual TSV review
flow.

Files:

* `knowledge.jsonl` is the deduplicated aggregate knowledge base.
* `runs/*.jsonl` are append-only per-run shards containing only rows learned in
  that invocation.
* `pending-human.jsonl` records agentic checks that failed or need confirmation.
* `index.json` stores portable run statistics.
* `../agentic-review/human-responses.jsonl` stores answers collected by
  `make agentic-pending`.

The generator learns from verified radare2 command output, r2js scripts,
radare2 source/docs/plugins, optional local radare2 book checkouts, optional
online resources, and bounded workflow/challenge experiments over fixtures under
`R2_SOURCE/test/bins`.

Paths are stored relative to `R2_SOURCE`; local home paths, temp paths, emails,
and usernames are sanitized before rows are written.
