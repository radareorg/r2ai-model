# Make targets

Run `make help` at the repository root for the short reference. The
[`r2ai-model` CLI](cli.md) is the preferred user interface; the Makefiles remain
useful for automation and compatibility. Command-line variable assignments are
forwarded to recursive invocations under `training/`.

## Root targets

| Target | Purpose |
| --- | --- |
| `make` / `make all` | Open `TSVFILE` in the manual pending-row review workflow. This is intentionally not the training target. |
| `make help` | Print all root targets, common variables, and the pointer to lower-level training help. |
| `make install` | Install a symlink to the checkout's `r2ai-model` executable under `BINDIR`. Use `sudo` when the destination requires it. |
| `make uninstall` | Remove the installed symlink from `BINDIR`. |
| `make preflight` | Compile and merge datasets, then validate every row with `CONFIG` without loading model weights. |
| `make train` | Install training dependencies, compile and merge datasets, fine-tune with `CONFIG`, and run the configured GGUF export. |
| `make chat` | Create or update `OLLAMA_MODEL` from `MODEL`, then open an Ollama chat. |
| `make serve` | Serve `MODEL` through the configured llama.cpp server. |
| `make agentic` | Discover source-grounded and executable knowledge and append accepted rows to the agentic knowledge base. |
| `make agentic-verify` | Re-run executable verification stored in the agentic knowledge rows. |
| `make agentic-pending` | Interactively inspect, answer, or drop unresolved agentic rows. |
| `make agentic-commands` | Refresh installed radare2 `?*` help and rebuild command, family, selection, focused, and workflow training rows. |
| `make agentic-r2cmd` | Verify only the fixed radare2-command seed dataset. |
| `make agentic-r2js` | Verify only the fixed r2js seed dataset. |
| `make agentic-reasoning` | Verify only the fixed long-reasoning seed dataset. |
| `make memory` | Ask one pending human-memory question interactively. |
| `make agentic-memory` | Print the next pending memory question in `MEMORY_FORMAT`. |
| `make agentic-memory-file` | Accept a JSON answer from `FILE`, `MEMORY_FILE`, or standard input. |
| `make memory-list` | List memory topics and their current status. |
| `make memory-export` | Convert accepted memory records into training-ready JSONL. |
| `make memory-add` | Queue a new `TOPIC`, with optional `QUESTION` and comma-separated `TAGS`. |
| `make memory-remember` | Directly store an accepted correction using `TOPIC`, `HIGHLIGHT`, and `DETAILS`. |

## Root variables

| Variable | Default | Used by |
| --- | --- | --- |
| `TSVFILE` | `data/radare2/pending/claude-numbers2.tsv` | `all` |
| `PREFIX` | `/usr/local` | Computes the default `BINDIR` for installation |
| `BINDIR` | `$(PREFIX)/bin` | `install`, `uninstall` |
| `DESTDIR` | empty | Optional staging root for `install` and `uninstall` |
| `CONFIG` | `config.yaml` under `training/` | `preflight`, `train` |
| `MODEL` | `radare2-qwen3-4b-finetuned.gguf` under `training/` | `chat`, `serve` |
| `OLLAMA_MODEL` | `r2ai-local` | `chat` |
| `AGENTIC_COMMANDS_ARGS` | empty | Extra arguments appended to `agentic-dataset.py commands` |
| `SOURCE` | `terminal` | Human-memory provenance label |
| `MEMORY_FORMAT` | `text` | `agentic-memory`; use `json` for agent automation |
| `FILE` | empty | Preferred answer file for `agentic-memory-file` |
| `MEMORY_FILE` | `-` | Fallback answer file; `-` reads standard input |
| `TOPIC`, `QUESTION`, `TAGS` | empty | `memory-add`; `TOPIC` is required |
| `HIGHLIGHT`, `DETAILS` | empty | `memory-remember`; both are required |

Examples:

```sh
make help
make agentic-commands AGENTIC_COMMANDS_ARGS="--ai off --memory-limit 0 --no-queue-memory"
make memory-add TOPIC="radare2 ESIL stepping" QUESTION="How does aesue stop?" TAGS="radare2,esil"
make agentic-memory MEMORY_FORMAT=json
make agentic-memory-file FILE=answer.json SOURCE=reviewer
make preflight CONFIG=config.minicpm5.yaml
make train CONFIG=config.yaml
make chat MODEL=radare2-qwen3-4b-finetuned.gguf OLLAMA_MODEL=r2ai-local
```

## Lower-level training targets

These targets live in `training/Makefile`. Run `make -C training help` to print
their short reference.

| Target | Purpose |
| --- | --- |
| `make -C training all` | Default alias for `train`. |
| `make -C training venv` | Create `training/venv`. |
| `make -C training deps` | Upgrade pip and install `training/requirements.txt`. |
| `make -C training compile-dataset` | Regenerate the classic command datasets. |
| `make -C training merge-agentic-dataset` | Compile and merge all eight training sources into `MERGED_DATASET`. |
| `make -C training preflight` | Merge and validate tokenizer/template compatibility without model weights. |
| `make -C training train` | Merge, train using `CONFIG`, and perform the configured export. |
| `make -C training train-agentic` | Backward-compatible alias for `train`. |
| `make -C training train-minicpm5` | Train with `config.minicpm5.yaml`. |
| `make -C training train-lfm25` | Train with `config.lfm2.5.yaml`. |
| `make -C training ollama-create` | Import `MODEL` into Ollama as `OLLAMA_MODEL`. |
| `make -C training chat` | Run `ollama-create`, then start an Ollama chat. |
| `make -C training llama-chat` | Start an interactive llama.cpp session with `MODEL`. |
| `make -C training serve` | Start llama.cpp's OpenAI-compatible server for `MODEL`. |
| `make -C training clean` | Remove the training virtual environment, output directories, and Python caches. |
| `make -C training help` | Print the lower-level target reference. |

Training-specific overrides include `MERGED_DATASET`, `LLAMA_CTX`,
`LLAMA_HOST`, `LLAMA_PORT`, `LLAMA_ARGS`, `LLAMA_CPP_BIN`, `LLAMA_CLI`, `LLAMA_SERVER`, and
`LLAMA_LIBRARY_PATH`. See `training/Makefile` defaults before overriding the
server binary or library path.
