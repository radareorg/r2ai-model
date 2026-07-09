# Makefile for Radare2 AI Model Training

.PHONY: all venv deps compile-dataset merge-agentic-dataset train train-agentic train-minicpm5 clean help
VPYTHON=$(shell pwd)/venv/bin/python3
VPIP=$(shell pwd)/venv/bin/pip3
CONFIG ?= config.yaml
MERGED_DATASET ?= ../data/training/radare2_all_agentic_train.jsonl

# Default target
all: venv deps compile-dataset train

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

# Merge all training-ready datasets, including agentic knowledge.
merge-agentic-dataset:
	@echo "Merging classic, verified, and agentic datasets into $(MERGED_DATASET)..."
	mkdir -p ../data/training
	cat \
		../data/radare2/radare2_train.jsonl \
		../data/radare2-agentic/verified.jsonl \
		../data/r2js/verified.jsonl \
		../data/reasoning-long/verified.jsonl \
		../data/agentic-knowledge/knowledge.jsonl \
		> $(MERGED_DATASET)
	@echo "Merged dataset written to $(MERGED_DATASET)."

# Train the model with the classic compiled dataset.
train: venv deps compile-dataset
	@echo "Starting model training with $(CONFIG)..."
	$(VPYTHON) train.py --config $(CONFIG)
	@echo "Training completed."

# Train against the merged agentic dataset. The selected config must point at $(MERGED_DATASET).
train-agentic: venv deps merge-agentic-dataset
	@echo "Starting agentic model training with $(CONFIG)..."
	$(VPYTHON) train.py --config $(CONFIG)
	@echo "Agentic training completed."

# Train MiniCPM5 on the merged agentic dataset.
train-minicpm5: CONFIG=config.minicpm5.yaml
train-minicpm5: train-agentic

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
	@echo "  all                    - Run complete classic pipeline (venv, deps, compile-dataset, train)"
	@echo "  venv                   - Create Python virtual environment"
	@echo "  deps                   - Install Python dependencies"
	@echo "  compile-dataset        - Compile the classic dataset from source scripts"
	@echo "  merge-agentic-dataset  - Merge classic, verified, and agentic JSONL datasets"
	@echo "  train                  - Train with CONFIG (default: config.yaml) after classic dataset compilation"
	@echo "  train-agentic          - Merge all agentic datasets and train with CONFIG"
	@echo "  train-minicpm5         - Train openbmb/MiniCPM5-1B with config.minicpm5.yaml"
	@echo "  clean                  - Clean up generated files and environments"
	@echo "  help                   - Show this help message"
	@echo ""
	@echo "Usage: make -C training [target]"
	@echo "Example: make -C training train-minicpm5"
