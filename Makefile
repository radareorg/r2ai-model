TSVFILE=data/radare2/pending/claude-numbers2.tsv
# TSVFILE=data/radare2/pending/r2gpt-advent.tsv
PREFIX?=/usr/local
BINDIR?=$(PREFIX)/bin
SOURCE?=terminal
QUESTION?=
TAGS?=
AGENTIC_COMMANDS_ARGS?=
MEMORY_FORMAT?=text
MEMORY_FILE?=-

.PHONY: all help install uninstall preflight train chat serve agentic agentic-verify agentic-pending agentic-commands agentic-r2cmd agentic-r2js agentic-reasoning memory agentic-memory agentic-memory-file memory-list memory-export memory-add memory-remember

all:
	./review-pending.sh "${TSVFILE}"

help:
	@printf '%s\n' \
		'r2ai-model make targets' \
		'' \
		'  make                              Review the default pending TSV (same as make all)' \
		'  make all                          Review TSVFILE with review-pending.sh' \
		'  make help                         Show this target and variable reference' \
		'' \
		'Installation:' \
		'  make install                      Install the r2ai-model symlink under BINDIR' \
		'  make uninstall                    Remove the installed r2ai-model symlink' \
		'' \
		'Training and inference:' \
		'  make preflight                    Merge data and validate CONFIG without loading model weights' \
		'  make train                        Merge all training data, train CONFIG, and export its GGUF' \
		'  make chat                         Import MODEL into Ollama and start an interactive chat' \
		'  make serve                        Serve MODEL through llama.cpp' \
		'' \
		'Agentic datasets:' \
		'  make agentic                      Discover and register new verified knowledge' \
		'  make agentic-verify               Re-run executable checks in registered knowledge' \
		'  make agentic-pending              Review unresolved agentic rows interactively' \
		'  make agentic-commands             Refresh ?* help and build command/workflow training rows' \
		'  make agentic-r2cmd                Verify only the fixed radare2-command seeds' \
		'  make agentic-r2js                 Verify only the fixed r2js seeds' \
		'  make agentic-reasoning            Verify only the fixed long-reasoning seeds' \
		'' \
		'Human memory:' \
		'  make memory                       Ask one pending memory question interactively' \
		'  make agentic-memory               Print the next pending question' \
		'  make agentic-memory-file          Accept an answer from FILE or standard input' \
		'  make memory-list                  List memory topics and their status' \
		'  make memory-export                Export accepted memories as training JSONL' \
		'  make memory-add                   Queue TOPIC and optional QUESTION/TAGS' \
		'  make memory-remember              Store an accepted TOPIC/HIGHLIGHT/DETAILS correction' \
		'' \
		'Common variables:' \
		'  TSVFILE=path                      Pending TSV used by make all' \
		'  PREFIX=/usr/local BINDIR=path     Installation prefix or exact binary directory' \
		'  DESTDIR=path                      Staging root for install/uninstall' \
		'  CONFIG=config.yaml                Training configuration forwarded to training/' \
		'  MODEL=model.gguf                  GGUF used by chat or serve' \
		'  OLLAMA_MODEL=name                 Ollama model name used by chat' \
		'  AGENTIC_COMMANDS_ARGS="..."       Extra agentic-dataset.py commands arguments' \
		'  SOURCE=name                       Source label stored with memory answers' \
		'  MEMORY_FORMAT=text|json           Output format for agentic-memory' \
		'  FILE=path MEMORY_FILE=path|-      Input for agentic-memory-file' \
		'  TOPIC=... QUESTION=... TAGS=...   Inputs for memory-add' \
		'  HIGHLIGHT=... DETAILS=...         Additional inputs for memory-remember' \
		'' \
		'Run make -C training help for lower-level training targets and variables.' \
		'See doc/make.md for examples and complete target notes.'

# Complete local-model workflows. Command-line CONFIG, MODEL, and OLLAMA_MODEL
# assignments are forwarded automatically by recursive make.
train:
	@$(MAKE) -C training train

preflight:
	@$(MAKE) -C training preflight

chat:
	@$(MAKE) -C training chat

serve:
	@$(MAKE) -C training serve

install:
	@mkdir -p "$(DESTDIR)$(BINDIR)"
	@ln -sfn "$(CURDIR)/r2ai-model" "$(DESTDIR)$(BINDIR)/r2ai-model"
	@echo "installed symlink $(DESTDIR)$(BINDIR)/r2ai-model -> $(CURDIR)/r2ai-model"

uninstall:
	@rm -f "$(DESTDIR)$(BINDIR)/r2ai-model"
	@echo "removed $(DESTDIR)$(BINDIR)/r2ai-model"

agentic:
	@./agentic-dataset.py build --skip-seeds

agentic-verify:
	@./agentic-dataset.py verify-knowledge

agentic-pending:
	./agentic-dataset.py pending

agentic-commands:
	@./agentic-dataset.py commands --queue-memory $(AGENTIC_COMMANDS_ARGS)

agentic-r2cmd:
	./agentic-dataset.py build --dataset r2cmd

agentic-r2js:
	./agentic-dataset.py build --dataset r2js

agentic-reasoning:
	./agentic-dataset.py build --dataset reasoning

memory:
	@./memory.py ask --source "$(SOURCE)"

agentic-memory:
	@./memory.py next --format "$(MEMORY_FORMAT)"

agentic-memory-file:
	@./memory.py answer-file --file "$(if $(FILE),$(FILE),$(MEMORY_FILE))" --source "$(SOURCE)"

memory-list:
	@./memory.py list

memory-export:
	@./memory.py export-training

memory-add:
	@test -n "$(TOPIC)" || (echo 'usage: make memory-add TOPIC="..." [QUESTION="..."] [TAGS="a,b"] [SOURCE=name]'; exit 1)
	@./memory.py add-topic "$(TOPIC)" --question "$(QUESTION)" --tags "$(TAGS)" --source "$(SOURCE)"

memory-remember:
	@test -n "$(TOPIC)" || (echo 'usage: make memory-remember TOPIC="..." HIGHLIGHT="..." DETAILS="..." [TAGS="a,b"] [SOURCE=name]'; exit 1)
	@test -n "$(HIGHLIGHT)" || (echo 'missing HIGHLIGHT'; exit 1)
	@test -n "$(DETAILS)" || (echo 'missing DETAILS'; exit 1)
	@./memory.py remember --topic "$(TOPIC)" --highlight "$(HIGHLIGHT)" --details "$(DETAILS)" --tags "$(TAGS)" --source "$(SOURCE)"
