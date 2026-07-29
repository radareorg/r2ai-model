# Makefile to create a venv, install deps, download a base model, build
# llama.cpp converter, and convert a model into a .gguf file.

PYTHON ?= python3
UV ?= uv
VENV := .venv
PY := $(UV) run python
REQ := requirements.txt

# Include a user config if present. Use config.mk to set BASE_MODEL, HF_TOKEN,
# quantization options, and other preferences.
ifneq (,$(wildcard config.mk))
include config.mk
endif

# Defaults (can be overridden in config.mk)
BASE_MODEL ?=
MODEL_DIR ?= ./model_cache/$(notdir $(BASE_MODEL))
DATA_DIR ?= ../data
OUTPUT_DIR ?= ./out
OUTPUT ?= $(OUTPUT_DIR)/model.gguf
HF_TOKEN ?=
LLAMA_REPO ?= https://github.com/ggerganov/llama.cpp.git
LLAMA_DIR ?= ./tools/llama.cpp
PYTORCH_INSTALL ?= cpu
QUANTIZE ?= Q4_K_M
LORA_MODEL_DIR ?= $(OUTPUT_DIR)/lora_model
MERGED_MODEL_DIR ?= $(OUTPUT_DIR)/merged_model
CONVERTER_SCRIPTS := convert_hf_to_gguf.py convert_llama_ggml_to_gguf.py convert_lora_to_gguf.py gguf-py/convert_hf_to_gguf.py
# Training parameters
BATCH_SIZE ?= 2
GRADIENT_ACCUMULATION ?= 4
LEARNING_RATE ?= 2e-4
NUM_EPOCHS ?= 1
MAX_STEPS ?= -1
LORA_R ?= 16
LORA_ALPHA ?= 16
MAX_SEQ_LENGTH ?= 2048

.PHONY: all maybe_copy_config venv install deps download_model train build_converter convert freeze-reqs clean

# If there's no config.mk but a sample exists, copy it and re-run make
maybe_copy_config:
	@if [ ! -f config.mk ] && [ -f config.mk.sample ]; then \
		cp config.mk.sample config.mk; \
		echo "Created config.mk from config.mk.sample"; \
		echo "Re-running make to pick up config.mk..."; \
		$(MAKE) all; \
		exit 0; \
	fi

all: maybe_copy_config install train

venv:
	@if [ ! -d "$(VENV)" ]; then \
		echo "Creating venv with uv..."; \
		$(UV) venv $(VENV); \
	else \
		echo "venv already exists at $(VENV)"; \
	fi

install: venv
	@echo "Checking installation..."
	@$(VENV)/bin/python -c "import torch, transformers, peft" && echo "✓ Packages installed!" || (echo "ERROR: Packages not installed"; exit 1)

deps: install

## Download model from Hugging Face (uses huggingface_hub.snapshot_download)
download_model: install
	@if [ -z "$(BASE_MODEL)" ]; then \
		echo "ERROR: BASE_MODEL is not set. Create config.mk or call: make download_model BASE_MODEL=meta-llama/Llama-2-7b"; \
		exit 1; \
	fi
	@echo "Downloading model '$(BASE_MODEL)' into $(MODEL_DIR) ..."
	@$(PY) scripts/download_model.py "$(BASE_MODEL)" "$(MODEL_DIR)" "$(HF_TOKEN)"

## Fine-tune with standard Transformers (multi-GPU compatible)
train: install build_converter
	@if [ -z "$(BASE_MODEL)" ]; then \
		echo "ERROR: BASE_MODEL is not set. Set it in config.mk"; \
		exit 1; \
	fi
	@if [ ! -d "$(DATA_DIR)" ]; then \
		echo "ERROR: DATA_DIR $(DATA_DIR) does not exist"; \
		exit 1; \
	fi
	@echo "Training $(BASE_MODEL) with Transformers on data from $(DATA_DIR)"
	@if command -v nvidia-smi >/dev/null 2>&1; then \
		GPU_COUNT=$$(nvidia-smi --query-gpu=name --format=csv,noheader | wc -l); \
		echo "Detected $$GPU_COUNT GPU(s)"; \
		if [ $$GPU_COUNT -gt 1 ]; then \
			echo "Using torchrun for multi-GPU training"; \
			$(VENV)/bin/torchrun --nproc_per_node=$$GPU_COUNT train.py \
			--base_model "$(BASE_MODEL)" \
			--data_dir "$(DATA_DIR)" \
			--output_dir "$(LORA_MODEL_DIR)" \
			--batch_size $(BATCH_SIZE) \
			--gradient_accumulation_steps $(GRADIENT_ACCUMULATION) \
			--learning_rate $(LEARNING_RATE) \
			--num_train_epochs $(NUM_EPOCHS) \
			--max_steps $(MAX_STEPS) \
			--lora_r $(LORA_R) \
			--lora_alpha $(LORA_ALPHA) \
			--max_seq_length $(MAX_SEQ_LENGTH); \
		else \
			echo "Using single GPU"; \
			$(PY) train.py \
			--base_model "$(BASE_MODEL)" \
			--data_dir "$(DATA_DIR)" \
			--output_dir "$(LORA_MODEL_DIR)" \
			--batch_size $(BATCH_SIZE) \
			--gradient_accumulation_steps $(GRADIENT_ACCUMULATION) \
			--learning_rate $(LEARNING_RATE) \
			--num_train_epochs $(NUM_EPOCHS) \
			--max_steps $(MAX_STEPS) \
			--lora_r $(LORA_R) \
			--lora_alpha $(LORA_ALPHA) \
			--max_seq_length $(MAX_SEQ_LENGTH); \
		fi; \
	else \
		echo "No GPU detected, using CPU (will be slow)"; \
		$(PY) train.py \
			--base_model "$(BASE_MODEL)" \
			--data_dir "$(DATA_DIR)" \
			--output_dir "$(LORA_MODEL_DIR)" \
			--batch_size $(BATCH_SIZE) \
			--gradient_accumulation_steps $(GRADIENT_ACCUMULATION) \
			--learning_rate $(LEARNING_RATE) \
			--num_train_epochs $(NUM_EPOCHS) \
			--max_steps $(MAX_STEPS) \
			--lora_r $(LORA_R) \
			--lora_alpha $(LORA_ALPHA) \
			--max_seq_length $(MAX_SEQ_LENGTH); \
	fi
	@echo "\n"
	@echo "Merging LoRA adapter and converting to GGUF..."
	@$(PY) scripts/merge_and_convert.py \
		--base_model "$(BASE_MODEL)" \
		--lora_adapter "$(LORA_MODEL_DIR)" \
		--output_dir "$(MERGED_MODEL_DIR)" \
		--gguf_output "$(OUTPUT)" \
		--llama_cpp_dir "$(LLAMA_DIR)" \
		--quantize "$(QUANTIZE)"

## Clone and build llama.cpp for conversion tools
build_converter:
	@if [ -d "$(LLAMA_DIR)" ]; then \
		echo "llama.cpp already cloned at $(LLAMA_DIR)"; \
	else \
		echo "Cloning llama.cpp into $(LLAMA_DIR)"; \
		git clone $(LLAMA_REPO) $(LLAMA_DIR); \
	fi
	@echo "Building llama.cpp..."
	@cd $(LLAMA_DIR) && mkdir -p build && cmake -S . -B build && cmake --build build --parallel $$(getconf _NPROCESSORS_ONLN) || (echo "Build failed; ensure CMake and a C compiler are installed" && exit 1)
	@echo "Installing llama.cpp Python converter requirements into venv..."
	@$(UV) pip install -r $(LLAMA_DIR)/requirements.txt || echo "Warning: installing llama.cpp requirements failed"

## Convert downloaded model to GGUF using the converter script present in llama.cpp
convert: build_converter download_model
	@echo "Running conversion wrapper..."
	@$(UV) run python scripts/convert_wrapper.py "$(LLAMA_DIR)" "$(BASE_MODEL)" "$(MODEL_DIR)" "$(OUTPUT)" "$(QUANTIZE)"

freeze-reqs: install
	@$(UV) pip freeze > $(REQ)
	@echo "Wrote $(REQ)"

clean:
	@echo "Removing venv, llama.cpp, model cache and outputs..."
	@rm -rf $(VENV) $(LLAMA_DIR) $(MODEL_DIR) $(OUTPUT_DIR)
