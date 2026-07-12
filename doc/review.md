# Review And Verification

Verify registered knowledge before training:

```sh
r2ai-model verify
```

Limit the verification pass when you only need a quick check:

```sh
r2ai-model verify --limit 50
```

Review pending agentic rows that need human confirmation:

```sh
r2ai-model review agentic
```

Pending review commands:

* `/skip`: keep the row pending.
* `/drop`: clear it without accepting an answer.
* `/quit`: stop reviewing.

To re-run fixed seed companion checks explicitly:

```sh
r2ai-model build --dataset r2cmd
r2ai-model build --dataset r2js
r2ai-model build --dataset reasoning
```

`r2ai-model review` without a queue name chooses the first non-empty queue:
agentic checks, memory questions, then the legacy TSV. These review operations
change source data but do not merge or fine-tune.
