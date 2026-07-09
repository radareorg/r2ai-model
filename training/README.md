# Radare2 AI Model Training

This directory contains the training pipeline for fine-tuning language models on Radare2 reverse engineering tasks.

## Project Structure

```
training/
├── config.yaml          # Default model, training, and export settings
├── config.minicpm5.yaml # MiniCPM5 agentic training settings
├── train.py            # Main training script
├── Makefile            # Automation script for the entire pipeline
└── README.md           # This file
```

## Quick Start

To run the classic training pipeline:

```bash
make -C training
```

To train from the merged agentic dataset:

```bash
make -C training train-agentic CONFIG=config.yaml
```

To train MiniCPM5 from the merged agentic dataset:

```bash
make -C training train-minicpm5
```

To chat with a trained GGUF through Ollama:

```bash
make -C training chat MODEL=radare2-smollm-finetuned.gguf
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

- Python 3.8+
- CUDA-compatible GPU (recommended for Linux)
- Sufficient disk space for model weights and datasets
- API keys for LLM services (if regenerating dataset from scratch)

## Configuration

Edit `config.yaml` to customize:

- **Model**: Change `model.name` to any Hugging Face causal LM, or use `config.minicpm5.yaml` for `openbmb/MiniCPM5-1B`
- **Training**: Adjust epochs, batch size, learning rate, etc.
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

To merge the classic, verified, and agentic datasets instead:

```bash
make -C training merge-agentic-dataset
```

`merge-agentic-dataset` writes `../data/training/radare2_all_agentic_train.jsonl`.

`compile-dataset` runs the dataset generation scripts from the parent directory:
- `parse_usage.py` - Parse radare2 command documentation
- `generate-dataset.py` - Generate Q&A pairs using LLMs
- `enrich-dataset.py` - Expand the dataset with variations
- `prepare-dataset.py` - Convert to JSONL format
- `r2cmd.py` - Convert to function calling format

### 3. Train Model
```bash
make -C training train
# or, for the merged agentic dataset
make -C training train-agentic CONFIG=config.yaml
# or MiniCPM5
make -C training train-minicpm5
```

### 4. Individual Targets
```bash
make -C training help                 # Show all available targets
make -C training merge-agentic-dataset # Build merged training JSONL
make -C training clean                # Clean up environment and outputs
make -C training chat MODEL=radare2-smollm-finetuned.gguf
make -C training serve MODEL=radare2-qwen3-4b-finetuned.gguf
```

## Dataset

The classic training target uses `../data/radare2/radare2_train.jsonl`. The agentic targets use `../data/training/radare2_all_agentic_train.jsonl`. This dataset contains:
- Questions about radare2 usage
- Corresponding radare2 commands as answers
- Conversational format with system prompts

## Model Export

### Linux/NVIDIA (GGUF)
- Exports to GGUF format using llama.cpp
- Supports various quantization levels (Q4_K_M, Q5_0, etc.)
- Optimized for GPU inference

### Mac (MLX)
- Exports to Apple's MLX format
- Optimized for Apple Silicon GPUs
- Requires MLX library

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