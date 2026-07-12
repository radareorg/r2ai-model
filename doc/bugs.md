# Bug-Hunt Leads

`R2BUGS.md` is the generated source-audit report produced by the agentic
pipeline. It records possible bug leads found while scanning radare2 source, but
it is not a list of confirmed vulnerabilities.

The generated block is delimited by:

```md
<!-- agentic-r2bugs:start -->
...
<!-- agentic-r2bugs:end -->
```

Keep manual notes outside those markers. `r2ai-model learn` may rewrite everything
inside the generated block.

## How `r2ai-model learn` Finds Leads

During `r2ai-model learn`, `agentic-dataset.py build --skip-seeds` calls the
agentic knowledge builder. Before writing new knowledge rows, it runs the source
bug-hunt report generator and updates `R2BUGS.md`.

The scan:

* walks selected radare2 source roots such as `libr/core`, `libr/main`,
  `libr/bin`, `libr/io`, `libr/util`, and `libr/include`;
* reads C/header/include-style files below the size cutoff;
* applies configured regex patterns from `BUG_HUNT_PATTERNS`;
* summarizes stable signals such as API names, sink markers, and TODO/XXX notes;
* writes one report section per matched bug-hunt family.

Current lead families include:

* shell command sinks around `r_sys_cmd*` APIs;
* script-output escaping around `r_cons_printf` output;
* memory-safety TODO/XXX notes mentioning leak, overflow, bounds, NULL, UAF,
  free, crash, or related terms.

Each generated section includes a stable reference, the regex pattern, current
hit counts, a compact signal summary, audit guidance, and required verification
steps.

## What It Is Not

`R2BUGS.md` does not prove a bug. A lead becomes actionable only after a human or
agent confirms:

* user-controlled or binary-controlled input reaches the suspicious sink;
* the behavior has security, correctness, or stability impact;
* there is a minimal r2/r2r reproducer or a narrowly scoped source patch.

Bug-hunt findings are intentionally kept out of
`data/agentic-knowledge/knowledge.jsonl`, so unconfirmed bug claims are not fed
back into training data.

## Useful Commands

```sh
# refresh knowledge and regenerate R2BUGS.md
r2ai-model learn

# scan a specific radare2 checkout
r2ai-model learn --r2-source ../radare2

# inspect generated report changes
git diff -- R2BUGS.md
```
