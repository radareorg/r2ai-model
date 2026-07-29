# Sample configuration for Makefile automation
# Copy this to `config.mk` or let `make` copy it automatically on first run.
#
# OPTIMIZED FOR: 2x RTX 5090 (32GB VRAM each, 64GB total)

# Base model to download (Hugging Face repo id)
# With 2x5090 (64GB VRAM total), you can train much larger models!
# Options: unsloth/gemma-3-270m-it (270M - trains VERY fast, as requested)
#          unsloth/gemma-3-27b-it (27B - much more powerful, slower training)
BASE_MODEL = google/gemma-3-270m

# Local directory to store the downloaded model files
MODEL_DIR = ./model_cache/$(notdir $(BASE_MODEL))

# Directory containing training data (TSV files)
DATA_DIR = ../data

# Where to place trained model and outputs
OUTPUT_DIR = ./out
LORA_MODEL_DIR = $(OUTPUT_DIR)/lora_model
OUTPUT = $(OUTPUT_DIR)/model.gguf

# Hugging Face token (optional). If empty, download will use public access.
# Required for gated models like Llama-2
HF_TOKEN =

# Repo and local dir for llama.cpp (converter)
LLAMA_REPO = https://github.com/ggerganov/llama.cpp.git
LLAMA_DIR = ./tools/llama.cpp

# PyTorch install preference: 'cpu' or 'cuda'
# Set to 'cuda' to use GPU acceleration (much faster!)
PYTORCH_INSTALL = cuda

# Quantization option for GGUF conversion (Q4_K_M, Q5_K_M, Q8_0, or none/f16)
QUANTIZE = Q4_K_M

# Training hyperparameters (optimized for 2x RTX 5090, 64GB total VRAM)
BATCH_SIZE = 16  # Increased for better GPU utilization
GRADIENT_ACCUMULATION = 2  # Less needed with larger batch size
LEARNING_RATE = 2e-4
NUM_EPOCHS = 3
MAX_STEPS = -1  # Set to positive number to override epochs
LORA_R = 32  # Increased rank for better fine-tuning quality
LORA_ALPHA = 32
MAX_SEQ_LENGTH = 2048  # Longer context with more VRAM

# You can override any of the above by creating a repo-local `config.mk`.
