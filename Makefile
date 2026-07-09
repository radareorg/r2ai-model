TSVFILE=data/radare2/pending/claude-numbers2.tsv
# TSVFILE=data/radare2/pending/r2gpt-advent.tsv

all:
	./review-pending.sh "${TSVFILE}"

agentic:
	@./agentic-dataset.py build --skip-seeds

agentic-verify:
	@./agentic-dataset.py verify-knowledge

agentic-pending:
	./agentic-dataset.py pending

agentic-r2cmd:
	./agentic-dataset.py build --dataset r2cmd

agentic-r2js:
	./agentic-dataset.py build --dataset r2js

agentic-reasoning:
	./agentic-dataset.py build --dataset reasoning
