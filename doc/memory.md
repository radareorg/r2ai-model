# Memory

`make memory` is the human clarification loop. It is intentionally transport
neutral: the terminal, a DeltaChat bot, a PicoClaw agent, or an Ollama wrapper
can all call the same CLI and write the same JSONL files.

## Commands

```sh
make memory
make agentic-memory
make agentic-memory MEMORY_FORMAT=json
make agentic-memory-file < answer.json
make agentic-memory-file FILE=answer.json
make memory-list
make memory-export
make memory-add TOPIC="radare2 ESIL stepping" QUESTION="How should 3aes be explained?" TAGS="radare2,esil"
make memory-remember TOPIC="radare2 ESIL stepping" HIGHLIGHT="3aes repeats aes three times" DETAILS="In radare2 a numeric prefix repeats the following command. aes is analysis/esil/step, so 3aes performs three ESIL steps." TAGS="radare2,esil"
```

## Files

* `data/memory/topics.jsonl`: queue of questions that need human clarification.
* `data/memory/memory.jsonl`: accepted source memories with highlight, details,
  tags, source channel, and training messages.
* `data/memory/verified.jsonl`: generated chat-format rows consumed by
  `make -C training merge-agentic-dataset`.

## Transport Contract

External agents can use the non-interactive protocol:

```sh
make agentic-memory MEMORY_FORMAT=json > question.json
make agentic-memory-file < answer.json
make agentic-memory-file FILE=answer.json
```

`make agentic-memory` prints the next pending topic, the exact question, tags,
source metadata, a JSON answer template, and the submit commands. The answer
payload must be JSON:

```json
{
  "id": "topic.id-from-agentic-memory",
  "highlight": "one sentence with the corrected or clarified fact",
  "details": "full explanation, examples, commands, caveats, and context",
  "tags": ["radare2", "command-grammar"]
}
```

`make agentic-memory-file` accepts one JSON object or a list of objects. It reads
from stdin by default, or from `FILE=answer.json`, marks topics answered, writes
`data/memory/memory.jsonl`, and refreshes `data/memory/verified.jsonl`.

Lower-level agents may also call these operations directly:

```sh
./memory.py next --format json
./memory.py answer-file --file - --source deltachat
./memory.py add-topic "topic" --question "question" --tags "tag1,tag2" --source deltachat
./memory.py remember --topic "topic" --highlight "short correction" --details - --tags "tag1,tag2" --source deltachat
./memory.py export-training
```

For `--details -`, pass the detailed explanation on stdin. This makes phone or
chat transports simple: collect the human answer, summarize the highlight, keep
the detailed correction, and let `memory.py` persist and export it.

The memory rows are not a bug tracker and are not raw chat logs. They are
curated facts, corrections, and workflow explanations that should influence
future training.
