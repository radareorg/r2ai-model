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

.PHONY: all install uninstall agentic agentic-verify agentic-pending agentic-commands agentic-r2cmd agentic-r2js agentic-reasoning memory agentic-memory agentic-memory-file memory-list memory-export memory-add memory-remember

all:
	./review-pending.sh "${TSVFILE}"

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
