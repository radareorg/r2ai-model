# Radare2 AI Model Training

This directory contains the training pipeline for fine-tuning language models on Radare2 reverse engineering tasks.

## Project Structure

```
training/
├── config.yaml          # Default model, training, and export settings
├── config.minicpm5.yaml # MiniCPM5 agentic training settings
├── config.lfm2.5.yaml   # LFM2.5-1.2B agentic training settings
├── train.py            # Main training script
├── Makefile            # Automation script for the entire pipeline
└── README.md           # This file
```

## Quick Start

From the repository root, run the complete default workflow:

```bash
make train
# or
r2ai-model train
```

This installs/repairs dependencies, rebuilds the merged training-ready dataset,
fine-tunes with LoRA, merges the adapter, and exports GGUF. Check tokenizer and
template compatibility first without loading model weights:

```bash
make preflight
r2ai-model preflight
```

To train MiniCPM5 from the merged agentic dataset:

```bash
make -C training train-minicpm5
```

To chat with a trained GGUF through Ollama:

```bash
make chat
# or
r2ai-model chat
```

To serve a GGUF through llama.cpp:

```bash
make -C training serve MODEL=radare2-qwen3-4b-finetuned.gguf
```

This will:
1. Create a Python virtual environment
2. Install all required dependencies
3. Compile the dataset from the parent directory's scripts
4. Fine-tune the model
5. Export to GGUF format (Linux/NVIDIA) or MLX format (Mac)

## Prerequisites

- Python 3.10+
- CUDA-compatible GPU (recommended for Linux)
- Sufficient disk space for model weights and datasets
- API keys for LLM services (if regenerating dataset from scratch)

## Configuration

Edit `config.yaml` to customize:

- **Model**: Select an instruct/chat causal LM whose fast tokenizer provides a
  chat template and supports tools; use preflight before training
- **Training**: Adjust epochs, batch size, learning rate, and activation-memory
  savings with `training.gradient_checkpointing`
- **Dataset context**: Adjust `dataset.max_length` (default 2048); batches use
  dynamic padding rather than padding every row to that limit
- **Evaluation split**: `dataset.test_split` assigns complete related-example
  groups deterministically using `dataset.split_seed`
- **Chat format**: Conversations use the selected tokenizer's native chat
  template and require a tokenizer with `chat_template` metadata
- **Loss masking**: System, user, and assistant-prompt tokens provide context
  but only assistant response and end-of-turn tokens contribute to loss
- **Tools**: Function definitions and assistant tool calls are preserved with
  structured arguments; the classic conversion stops before any unavailable
  tool result
- **Quantization**: Set GGUF quantization method
- **Platform**: Configure CUDA/MPS settings
- **LoRA**: Enable parameter-efficient fine-tuning

MiniCPM5 uses the standard Llama causal-LM architecture, but its model card recommends `transformers>=5.6`; the requirements files use that floor.

## Manual Usage

### 1. Setup Environment
```bash
make -C training venv
source training/venv/bin/activate
make -C training deps
```

### 2. Compile Dataset
```bash
make -C training compile-dataset
```

To merge the classic, verified, agentic, command, and memory datasets instead:

```bash
make -C training merge-agentic-dataset
```

`merge-agentic-dataset` refreshes `../data/memory/verified.jsonl` and writes `../data/training/radare2_all_agentic_train.jsonl`.

`compile-dataset` runs the dataset generation scripts from the parent directory:
- `parse_usage.py` - Parse radare2 command documentation
- `generate-dataset.py` - Generate Q&A pairs using LLMs
- `enrich-dataset.py` - Expand the dataset with variations
- `prepare-dataset.py` - Convert to JSONL format
- `r2cmd.py` - Convert to function calling format

### 3. Train Model
```bash
make -C training train
# or MiniCPM5
make -C training train-minicpm5
# or LFM2.5
make -C training train-lfm25
```

### 4. Individual Targets
```bash
make -C training help                 # Show all available targets
make memory-export                       # Optional; merge-agentic-dataset refreshes this too
make -C training merge-agentic-dataset # Build merged training JSONL
make -C training clean                # Clean up environment and outputs
make -C training chat
make -C training serve MODEL=radare2-qwen3-4b-finetuned.gguf
```

## Dataset

All included training targets use
`../data/training/radare2_all_agentic_train.jsonl`. This dataset contains:
- Questions about radare2 usage
- Corresponding radare2 commands as answers
- Verified agentic knowledge and command workflows
- Command grammar rows from `data/agentic-commands/verified.jsonl`
- Human memory corrections from `data/memory/verified.jsonl`
- Conversational format with system prompts

## Model Export

### Linux/NVIDIA (GGUF)
- Exports to GGUF format using llama.cpp
- Supports various quantization levels (Q4_K_M, Q5_0, etc.)
- Optimized for GPU inference

### Mac (MLX)
- MLX export is not implemented by `train.py` yet; use the model vendor's MLX
  conversion/runtime until that exporter is added

## Platform Support

- **Linux + NVIDIA**: Full CUDA acceleration, GGUF export
- **macOS**: MPS acceleration, MLX export (experimental)
- **Other platforms**: CPU-only training, limited export options

## Troubleshooting

### Common Issues

1. **CUDA out of memory**: Reduce `per_device_train_batch_size` or increase `gradient_accumulation_steps`

2. **Dataset compilation fails**: Ensure API keys are set for LLM services, or use existing compiled dataset

3. **GGUF export fails**: Install llama.cpp and ensure it's in PATH

4. **MLX export fails**: Install Apple's MLX library

### Performance Tips

- Use LoRA for memory-efficient fine-tuning on large models
- Adjust batch size based on GPU memory
- Use gradient checkpointing for very large models
- Monitor training with TensorBoard (logs saved to output_dir)

## Project Organization Suggestions

The current project structure could be improved:

### Recommended Structure
```
r2ai-model/
├── data/
│   ├── radare2/
│   │   ├── sources/          # Raw data files
│   │   ├── processed/        # Intermediate processed data
│   │   └── final/            # Final datasets
│   └── scripts/              # Data processing scripts
├── training/
│   ├── configs/              # Multiple config files for different setups
│   ├── scripts/              # Training utilities
│   └── models/               # Saved model checkpoints
├── evaluation/               # Model evaluation scripts
├── inference/                # Inference and deployment scripts
└── docs/                     # Documentation
```

### Improvements
1. **Modularize dataset generation**: Separate LLM calls from data processing
2. **Add data validation**: Quality checks for generated datasets
3. **Version control for datasets**: Track dataset versions and changes
4. **Experiment tracking**: Log hyperparameters and results
5. **CI/CD pipeline**: Automated testing and deployment
6. **Model registry**: Store and version trained models

## Contributing

1. Test changes on both Linux and Mac platforms
2. Update documentation for any configuration changes
3. Add validation for new configuration options
4. Ensure backward compatibility with existing configs

## License

This project follows the same license as the parent Radare2 project.
