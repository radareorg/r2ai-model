# r2js dataset

This dataset teaches radare2's embedded JavaScript runtime.

Important source anchors in radare2:

- `libr/core/cmd.c`: `js`, `js:`, `js-`, and `.r2.js` dispatch.
- `shlr/qjs/`: bundled QuickJS runtime and r2papi support.
- `scripts/*.r2.js`: real scripts using `r2.cmd`, `r2.cmdj`, `r2.callAt`,
  `r2.cmdAt`, `r2.syscmds`, and `r2.plugin`.

Run:

```sh
../../agentic-dataset.py build --dataset r2js
```

Rows are promoted to `verified.jsonl` only after the script runs in radare2 and
matches the declared checks.
