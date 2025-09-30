# Makefile to create a venv, install deps, download a base model, build
# llama.cpp converter, and convert a model into a .gguf file.

PYTHON ?= python3
VENV := ./venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
REQ := requirements.txt

# Include a user config if present. Use config.mk to set BASE_MODEL, HF_TOKEN,
# quantization options, and other preferences.
ifneq (,$(wildcard config.mk))
include config.mk
endif

# Defaults (can be overridden in config.mk)
BASE_MODEL ?=
MODEL_DIR ?= ./model_cache/$(notdir $(BASE_MODEL))
OUTPUT_DIR ?= ./out
OUTPUT ?= $(OUTPUT_DIR)/model.gguf
HF_TOKEN ?=
LLAMA_REPO ?= https://github.com/ggerganov/llama.cpp.git
LLAMA_DIR ?= ./tools/llama.cpp
PYTORCH_INSTALL ?= cpu
QUANTIZE ?= none
CONVERTER_SCRIPTS := convert_hf_to_gguf.py convert_llama_ggml_to_gguf.py convert_lora_to_gguf.py gguf-py/convert_hf_to_gguf.py

.PHONY: all maybe_copy_config venv install deps download_model build_converter convert freeze-reqs clean

# If there's no config.mk but a sample exists, copy it and re-run make
maybe_copy_config:
	@if [ ! -f config.mk ] && [ -f config.mk.sample ]; then \
		cp config.mk.sample config.mk; \
		echo "Created config.mk from config.mk.sample"; \
		echo "Re-running make to pick up config.mk..."; \
		$(MAKE) all; \
		exit 0; \
	fi

all: maybe_copy_config install download_model build_converter convert

venv:
	@if [ ! -d "$(VENV)" ]; then $(PYTHON) -m venv $(VENV) && echo "Created venv at $(VENV)"; else echo "venv already exists at $(VENV)"; fi

install: venv
	@echo "Upgrading pip and installing essential Python packages..."
	$(PIP) install --upgrade pip setuptools wheel
	@if [ -f $(REQ) ]; then \
		echo "Installing from $(REQ)"; \
		$(PIP) install -r $(REQ); \
	else \
		echo "Installing core ML tooling into venv"; \
		$(PIP) install transformers huggingface_hub safetensors sentencepiece accelerate; \
		if [ "$(PYTORCH_INSTALL)" = "cpu" ]; then \
			$(PIP) install --index-url https://download.pytorch.org/whl/cpu torch; \
		else \
			echo "Please set PYTORCH_INSTALL appropriately in config.mk for CUDA wheels"; \
		fi; \
	fi

deps: install

## Download model from Hugging Face (uses huggingface_hub.snapshot_download)
download_model: install
	@if [ -z "$(BASE_MODEL)" ]; then \
		echo "ERROR: BASE_MODEL is not set. Create config.mk or call: make download_model BASE_MODEL=meta-llama/Llama-2-7b"; \
		exit 1; \
	fi
	@echo "Downloading model '$(BASE_MODEL)' into $(MODEL_DIR) ..."
		@$(PY) scripts/download_model.py "$(BASE_MODEL)" "$(MODEL_DIR)" "$(HF_TOKEN)"

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
	@$(PIP) install -r $(LLAMA_DIR)/requirements.txt || echo "Warning: installing llama.cpp requirements failed"

## Convert downloaded model to GGUF using the converter script present in llama.cpp
convert: build_converter download_model
	@echo "Running conversion wrapper..."
	@"$(PY)" scripts/convert_wrapper.py "$(LLAMA_DIR)" "$(BASE_MODEL)" "$(MODEL_DIR)" "$(OUTPUT)" "$(QUANTIZE)"

freeze-reqs: install
	@$(PIP) freeze > $(REQ)
	@echo "Wrote $(REQ)"

clean:
	@echo "Removing venv, llama.cpp, model cache and outputs..."
	@rm -rf $(VENV) $(LLAMA_DIR) $(MODEL_DIR) $(OUTPUT_DIR)
