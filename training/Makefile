# Makefile for Radare2 AI Model Training

.PHONY: all venv deps compile-dataset merge-agentic-dataset preflight train train-agentic train-minicpm5 train-lfm25 chat ollama-create serve clean help
VPYTHON=$(shell pwd)/venv/bin/python3
VPIP=$(shell pwd)/venv/bin/pip3
CONFIG ?= config.yaml
MERGED_DATASET ?= ../data/training/radare2_all_agentic_train.jsonl
MODEL ?= radare2-qwen3-4b-finetuned.gguf
MODEL_PATH := $(abspath $(MODEL))
OLLAMA_MODEL ?= r2ai-local
LLAMA_CTX ?= 4096
LLAMA_HOST ?= 127.0.0.1
LLAMA_PORT ?= 8080
LLAMA_ARGS ?=
LLAMA_CPP_BIN ?= $(firstword $(wildcard /home/pancake/.unsloth/llama.cpp/build/bin ../../llama.cpp/build/bin ../llama.cpp/build/bin))
ifeq ($(LLAMA_CPP_BIN),)
LLAMA_SERVER ?= llama-server
LLAMA_LIBRARY_PATH ?= .
else
LLAMA_SERVER ?= $(LLAMA_CPP_BIN)/llama-server
LLAMA_LIBRARY_PATH ?= $(LLAMA_CPP_BIN)
endif

# Default target
all: train

# Create virtual environment
venv:
	@echo "Creating Python virtual environment..."
	python3 -m venv venv
	@echo "Virtual environment created. Activate with: source venv/bin/activate"

# Install dependencies
deps: venv
	@echo "Installing dependencies..."
	$(VPIP) install --upgrade pip
	$(VPIP) install -r requirements.txt
	@echo "Dependencies installed."

# Compile dataset
compile-dataset:
	@echo "Compiling dataset..."
	# Run dataset generation scripts
	#cd .. && $(VPYTHON) parse_usage.py # This may require API keys for LLMs
	#cd .. && $(VPYTHON) generate-dataset.py  # This may require API keys for LLMs
	# cd .. && $(VPYTHON) enrich-dataset.py
	cd .. && $(VPYTHON) prepare-dataset.py
	cd .. && $(VPYTHON) r2cmd.py
	@echo "Dataset compilation completed."

# Merge all training-ready chat, tool-calling, agentic, command, and memory datasets.
merge-agentic-dataset: compile-dataset
	@echo "Merging chat, tool-calling, agentic, command, and memory datasets into $(MERGED_DATASET)..."
	mkdir -p ../data/training
	mkdir -p ../data/agentic-commands
	touch ../data/agentic-commands/verified.jsonl
	cd .. && ./memory.py export-training
	python3 merge_datasets.py --output $(MERGED_DATASET) \
		../data/radare2/function_calling_r2cmd_dataset.jsonl \
		../data/radare2/radare2_train.jsonl \
		../data/radare2-agentic/verified.jsonl \
		../data/r2js/verified.jsonl \
		../data/reasoning-long/verified.jsonl \
		../data/agentic-knowledge/knowledge.jsonl \
		../data/agentic-commands/verified.jsonl \
		../data/memory/verified.jsonl
	@echo "Merged dataset written to $(MERGED_DATASET)."

# Train the default model with every training-ready dataset.
train: venv deps merge-agentic-dataset
	@echo "Starting model training with $(CONFIG)..."
	$(VPYTHON) train.py --config $(CONFIG)
	@echo "Training completed."

# Validate tokenizer/template compatibility without loading model weights.
preflight: venv deps merge-agentic-dataset
	$(VPYTHON) train.py --config $(CONFIG) --preflight

# Backward-compatible name for the merged-dataset training workflow.
train-agentic: train

# Train MiniCPM5 on the merged agentic dataset.
train-minicpm5: CONFIG=config.minicpm5.yaml
train-minicpm5: train

# Train LFM2.5-1.2B-Instruct on the merged dataset.
train-lfm25: CONFIG=config.lfm2.5.yaml
train-lfm25: train

# Import the selected GGUF into Ollama. The default matches config.yaml.
ollama-create:
	@test -f "$(MODEL_PATH)" || (echo "Missing MODEL=$(MODEL_PATH)"; exit 1)
	@printf 'FROM %s\nPARAMETER num_ctx %s\nSYSTEM """You are a radare2 reverse engineering assistant. Prefer precise radare2 commands and explain validation evidence."""\n' "$(MODEL_PATH)" "$(LLAMA_CTX)" > .ollama-Modelfile
	ollama create $(OLLAMA_MODEL) -f .ollama-Modelfile

# Chat with the selected GGUF via Ollama. Override MODEL=... and OLLAMA_MODEL=... as needed.
chat: ollama-create
	ollama run $(OLLAMA_MODEL)

# Serve the selected GGUF with llama.cpp's OpenAI-compatible server.
serve:
	@test -f "$(MODEL_PATH)" || (echo "Missing MODEL=$(MODEL_PATH)"; exit 1)
	LD_LIBRARY_PATH="$(LLAMA_LIBRARY_PATH):$${LD_LIBRARY_PATH}" "$(LLAMA_SERVER)" -m "$(MODEL_PATH)" -c $(LLAMA_CTX) --host $(LLAMA_HOST) --port $(LLAMA_PORT) $(LLAMA_ARGS)

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf venv
	rm -rf output
	rm -rf output-minicpm5
	rm -rf __pycache__
	rm -rf *.pyc
	@echo "Cleanup completed."

# Help
help:
	@echo "Available targets:"
	@echo "  all                    - Install dependencies, merge training data, train, and export"
	@echo "  venv                   - Create Python virtual environment"
	@echo "  deps                   - Install Python dependencies"
	@echo "  compile-dataset        - Compile the classic dataset from source scripts"
	@echo "  merge-agentic-dataset  - Merge classic, verified, agentic, command, and memory JSONL datasets"
	@echo "  train                  - Install dependencies, merge all training-ready data, and train with CONFIG"
	@echo "  preflight              - Validate CONFIG tokenizer/template compatibility without model weights"
	@echo "  train-agentic          - Backward-compatible alias for train"
	@echo "  train-minicpm5         - Train openbmb/MiniCPM5-1B with config.minicpm5.yaml"
	@echo "  train-lfm25            - Train LiquidAI/LFM2.5-1.2B-Instruct with config.lfm2.5.yaml"
	@echo "  chat                   - Import MODEL into Ollama and run an interactive chat"
	@echo "  serve                  - Serve MODEL with llama.cpp server"
	@echo "  clean                  - Clean up generated files and environments"
	@echo "  help                   - Show this help message"
	@echo ""
	@echo "Usage: make -C training [target]"
	@echo "Example: make -C training chat"
