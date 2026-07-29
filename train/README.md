# Fine-tuning LLMs for radare2 using Transformers + PEFT

This repository includes a `Makefile` that uses `uv` (ultra-fast Python package manager) to set up dependencies, train models with Transformers and PEFT (LoRA), and convert checkpoints to `.gguf` format. Optimized for multi-GPU training.

## Prerequisites
- **Python 3.10+** installed
- **uv** package manager - install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- **CUDA** (optional but recommended for GPU training)
- **2x RTX 5090** or other NVIDIA GPUs for fast training

## Quick Start (just run `make`!)

**Training is as simple as:**

```bash
cd train
make  # Creates .venv with uv, installs deps, and starts training!
```

The default config trains `google/gemma-3-270m` on all TSV files in `../data`.

### Configuration

Edit `config.mk` (auto-created from `config.mk.sample`) to customize:

```makefile
BASE_MODEL = google/gemma-3-270m      # Or google/gemma-3-27b for larger model
DATA_DIR = ../data                    # Your training data (TSV files)
BATCH_SIZE = 16                       # Per-GPU batch size
NUM_EPOCHS = 3                        # Training epochs
LORA_R = 32                           # LoRA rank (higher = better quality)
MAX_SEQ_LENGTH = 2048                 # Context length
QUANTIZE = Q4_K_M                     # GGUF quantization (Q4_K_M, Q5_K_M, Q8_0, or f16)
```

### Multi-GPU Training

The Makefile automatically detects and uses all available GPUs:

```bash
make train  # Uses torchrun with all GPUs automatically
```

### What `make train` does

1. **Trains** the model with LoRA on your data
2. **Tests** the model with inference examples
3. **Merges** LoRA adapter with base model
4. **Converts** to GGUF format (Q4_K_M quantization by default)
5. **Outputs** final GGUF file to `./out/model.gguf`

### Individual Steps

```bash
make install          # Install dependencies with uv (very fast!)
make train            # Full pipeline: train + test + merge + convert to GGUF
make clean            # Remove venv, cache, outputs
```

## Why uv?

- **10-100x faster** than pip for package installation
- **Better dependency resolution** with conflict detection
- **Drop-in replacement** for pip/venv workflows
- **Works with existing requirements.txt** and pyproject.toml

## Training Details

### Data Format

Training data is loaded from TSV files with this format:

```tsv
Category	Question	Command
Code Analysis	How do I get function size?	?v $FS
Exploit Dev	How do I calculate offset to return address?	?v $r{rsp}-$B
```

All `.tsv` files in `DATA_DIR` are automatically discovered and loaded (excluding `.tsv.ignored` and `.tsv.ok` files).

### Model Output

After training completes, you'll have:
- `./out/model.gguf` - **Ready-to-use GGUF model** (quantized, merged)
- `./out/lora_model/` - LoRA adapter (adapter_model.safetensors, config)
- `./out/merged_model/` - Full merged model in HuggingFace format
- `./out/lora_model/training_metadata.json` - Training info

### GPU Requirements

- **Gemma-3-270M**: ~4GB VRAM (runs on any GPU)
- **Gemma-3-27B**: ~16GB VRAM with 4-bit quantization
- **Multi-GPU**: Automatically uses DDP (Distributed Data Parallel)

## Troubleshooting

**RTX 5090 CUDA compatibility warning**: The RTX 5090 is very new (sm_120). PyTorch 2.6 doesn't fully support it, but training still works. For full support, use PyTorch nightly:

```bash
uv pip install --pre torch torchvision --index-url https://download.pytorch.org/whl/nightly/cu124
```

**Out of memory**: Reduce `BATCH_SIZE` or `MAX_SEQ_LENGTH` in `config.mk`

**Slow training on CPU**: Make sure `PYTORCH_INSTALL=cuda` is set in `config.mk`

