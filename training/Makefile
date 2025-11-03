# Makefile for Radare2 AI Model Training

.PHONY: all venv deps compile-dataset train clean help
VPYTHON=$(shell pwd)/venv/bin/python3
VPIP=$(shell pwd)/venv/bin/pip3

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

# Train the model
train: venv deps compile-dataset
	@echo "Starting model training..."
	$(VPYTHON) train.py
	@echo "Training completed."

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf venv
	rm -rf output
	rm -rf __pycache__
	rm -rf *.pyc
	@echo "Cleanup completed."

# Help
help:
	@echo "Available targets:"
	@echo "  all             - Run complete pipeline (venv, deps, compile-dataset, train)"
	@echo "  venv            - Create Python virtual environment"
	@echo "  deps            - Install Python dependencies"
	@echo "  compile-dataset - Compile the dataset from source scripts"
	@echo "  train           - Train the model"
	@echo "  clean           - Clean up generated files and environments"
	@echo "  help            - Show this help message"
	@echo ""
	@echo "Usage: make -C training [target]"
	@echo "Example: make -C training all"
