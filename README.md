# r2ai-model

Collection of data sources to generate a dataset for training and finetuning LLM models to use radare2.

## Organization

Dataset is stored in Q/A form (Question/Answer) separating them by tabs (TSV) where the question is phrased in English and the answer is an r2 oneliner to be executed by r2ai in auto mode.

* / -> root directory, scripts to generate raw QA
* `data/radare2_ok.tsv` -> validated statements
* `data/radare2_todo.tsv` -> unanswered questions
* data/Attic/ -> already processed files
* data/sources -> unfiltered data sources to be used to generate questions

## Agentic generation

The manual review flow remains the default `make` target. For faster generation
with local verification, use:

```sh
make agentic
```

This runs `agentic-dataset.py build`, which executes r2 commands and r2js
scripts against fixtures under `R2_SOURCE/test/bins` before writing
training rows. Verified companion datasets live in:

* `data/radare2-agentic/` -> action to r2 command examples with evidence.
* `data/r2js/` -> examples and Q/A for radare2's QuickJS runtime.
* `data/reasoning-long/` -> multi-step reverse engineering, forensics,
  firmware, and vulnerability research tasks.
* `data/agentic-knowledge/` -> generated r2 help and r2js source knowledge,
  rebuilt from `R2_SOURCE` by `make agentic`.
* `data/agentic-review/` -> agentic-only questions and failed checks for human review.

Optional AI proposal mode:

```sh
OPENAI_API_KEY=... ./agentic-dataset.py propose --count 20
```

AI proposals are written as agentic-only pending rows and must still pass the
local verifier before they are promoted to training data.
