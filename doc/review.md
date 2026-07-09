# Review And Verification

Verify registered knowledge before training:

```sh
make agentic-verify
```

Limit the verification pass when you only need a quick check:

```sh
AGENTIC_VERIFY_LIMIT=50 make agentic-verify
```

Review pending agentic rows that need human confirmation:

```sh
make agentic-pending
```

Pending review commands:

* `/skip`: keep the row pending.
* `/drop`: clear it without accepting an answer.
* `/quit`: stop reviewing.

To re-run fixed seed companion checks explicitly:

```sh
make agentic-r2cmd
make agentic-r2js
make agentic-reasoning
```
