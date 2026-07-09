# Agentic Knowledge Base

`make agentic` grows this directory. It does not replace the manual TSV review
flow.

Files:

* `knowledge.jsonl` is the deduplicated, quality-filtered aggregate knowledge
  base and the preferred training input.
* `runs/*.jsonl` are append-only per-run audit shards containing accepted rows
  learned in that invocation.
* `pending-human.jsonl` records agentic checks that failed or need confirmation.
* `index.json` stores portable run statistics.
* `../agentic-review/human-responses.jsonl` stores answers collected by
  `make agentic-pending`.

The generator learns from human-reviewed pending answers, verified radare2
command output, r2js scripts, radare2 source/docs/plugins, source xrefs,
radare2's maintained `test/db` regression tests,
optional local radare2 book checkouts, optional online resources, and curated
workflow/challenge experiments over fixtures
under `R2_SOURCE/test/bins`.
`make agentic` prints each accepted new row id, source refs, question, answer,
and verification summary so growth is reviewable in the terminal. Generic
fixture sweeps are opt-in because they can
produce repetitive low-value rows.

Quality gates dedupe by id and content fingerprint, prune generic
`fixture.triage` rows, reject navigation-heavy online pages, summarize plugin
source rows without raw code dumps, extract concise signal-bearing lines from
documentation, mine regression tests round-robin across categories while
capping rows per source file, and cap per-section growth so one category cannot
fill the whole run budget. Source bug-hunt findings are written to `../../R2BUGS.md`
instead of this training knowledge base.

Paths are stored relative to `R2_SOURCE`; local home paths, temp paths, emails,
and usernames are sanitized before rows are written.
