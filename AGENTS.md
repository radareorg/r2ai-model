# Agent Commands

Use `r2ai-model` as the primary interface. Run these first when orientation is
needed:

```sh
r2ai-model help
r2ai-model status
r2ai-model datasets
```

The data flow is:

```text
source datasets -> merge -> preflight (optional) -> train -> GGUF -> chat/serve
```

`train` already compiles and merges. The shortest fine-tuning workflow is:

```sh
r2ai-model train --preset qwen
```

Use preflight before an expensive run when source data or model templates
changed:

```sh
r2ai-model preflight --preset qwen
r2ai-model train --preset qwen
```

Source-dataset growth is separate and optional:

```sh
r2ai-model refresh-commands --ai off --no-queue-memory
r2ai-model learn
r2ai-model verify
r2ai-model review
```

`refresh-commands` rebuilds command training rows from radare2 help and verified
workflows; it does not list commands or train a model. `commands` is retained as
an alias. `learn` grows broader agentic knowledge. `review` records human
decisions and corrections.

Batch agents can process memory questions through JSON:

```sh
r2ai-model next --format json > question.json
r2ai-model answer < answer.json
```

Use trained artifacts with:

```sh
r2ai-model chat --preset qwen
r2ai-model serve --preset qwen --port 8080
```

Alternative presets are `minicpm5` and `lfm25`. Custom configs are relative to
`training/` unless absolute:

```sh
r2ai-model train --config custom.yaml
```

Keep generated bug leads in `R2BUGS.md` out of training unless manually
confirmed and converted into reviewed rows. Train from aggregate knowledge and
verified files, not `runs/*.jsonl` audit shards. Do not commit virtual
environments, merged datasets, output directories, or GGUF files.

Makefiles remain compatibility and automation layers:

```sh
make help
make -C training help
```
