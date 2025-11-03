#!/usr/bin/env python3
"""
Fine-tuning script for Radare2 AI Model

This script fine-tunes a configurable Hugging Face model on the Radare2 dataset
and exports it to GGUF format (Linux/NVIDIA) or MLX format (Mac).
"""

import json
import os
import platform
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Optional

import torch
import yaml
from datasets import DatasetDict, load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)

def load_config(config_path: str = "config.yaml"):
    """Load configuration from YAML file."""
    path = Path(config_path)
    with open(path, 'r') as f:
        config = yaml.safe_load(f)
    config['_config_path'] = str(path.resolve())
    return config


def _resolve_dataset_path(config) -> Path:
    """Resolve dataset path relative to the config file."""
    dataset_path = Path(config['dataset']['path'])
    if not dataset_path.is_absolute():
        config_dir = Path(config['_config_path']).parent
        dataset_path = (config_dir / dataset_path).resolve()
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found at {dataset_path}")
    return dataset_path


def _build_training_metadata(config, dataset_path: Path, final_model_path: Path) -> dict:
    """Create a metadata snapshot to detect stale training artifacts."""
    dataset_stat = dataset_path.stat()
    relevant = {
        "model": config.get("model"),
        "dataset": {
            "path": str(dataset_path),
            "test_split": config['dataset'].get('test_split'),
        },
        "training": config.get("training"),
        "lora": config.get("lora"),
    }
    config_fingerprint = sha256(
        json.dumps(relevant, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    metadata = {
        "model_name": config['model']['name'],
        "tokenizer": config['model'].get('tokenizer'),
        "dataset_path": str(dataset_path),
        "dataset_mtime": dataset_stat.st_mtime,
        "dataset_size": dataset_stat.st_size,
        "config_fingerprint": config_fingerprint,
        "final_model_path": str(final_model_path.resolve()),
    }
    return metadata


def _load_cached_metadata(metadata_path: Path) -> Optional[dict]:
    """Load cached metadata if it exists and is readable."""
    if not metadata_path.is_file():
        return None
    try:
        with open(metadata_path, 'r') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _final_model_is_complete(final_model_path: Path) -> bool:
    """Check that the final model directory contains the expected artifacts."""
    if not final_model_path.is_dir():
        return False
    essential_files = ["config.json", "tokenizer.json"]
    if not all((final_model_path / name).exists() for name in essential_files):
        return False
    has_weights = list(final_model_path.glob("model*.safetensors")) or list(final_model_path.glob("pytorch_model*.bin"))
    return bool(has_weights)


def _metadata_matches(cached: dict, current: dict) -> bool:
    """Compare cached metadata with the current configuration snapshot."""
    required_keys = [
        "model_name",
        "tokenizer",
        "dataset_path",
        "dataset_mtime",
        "dataset_size",
        "config_fingerprint",
        "final_model_path",
    ]
    for key in required_keys:
        if cached.get(key) != current.get(key):
            return False
    final_model_path = Path(cached["final_model_path"])
    return _final_model_is_complete(final_model_path)


def _write_metadata(metadata_path: Path, metadata: dict) -> None:
    """Persist metadata to disk."""
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)


def _latest_mtime_in_directory(path: Path) -> float:
    """Return the latest modification time for any file in a directory."""
    latest = 0.0
    if not path.is_dir():
        return latest
    for file in path.rglob("*"):
        if file.is_file():
            latest = max(latest, file.stat().st_mtime)
    return latest

def setup_model_and_tokenizer(config):
    """Setup model and tokenizer based on config."""
    model_name = config['model']['name']
    tokenizer_name = config['model'].get('tokenizer') or model_name

    print(f"Loading model: {model_name}")
    print(f"Loading tokenizer: {tokenizer_name}")

    tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        device_map="auto" if torch.cuda.is_available() else None,
    )

    # Apply LoRA if enabled
    if config.get('lora', {}).get('use_lora', False):
        lora_config = LoraConfig(
            r=config['lora']['r'],
            lora_alpha=config['lora']['lora_alpha'],
            target_modules=config['lora']['target_modules'],
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = prepare_model_for_kbit_training(model)
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

    return model, tokenizer

def load_and_prepare_dataset(config, tokenizer):
    """Load and prepare the dataset."""
    dataset_path = Path(config['dataset']['path'])

    print(f"Loading dataset from: {dataset_path}")

    # Load JSONL dataset
    dataset = load_dataset('json', data_files=str(dataset_path))

    def tokenize_function(examples):
        # For conversational format, we need to handle messages
        texts = []
        for messages in examples['messages']:
            conversation = ""
            for msg in messages:
                role = msg['role']
                content = msg['content']
                if role == 'system':
                    conversation += f"System: {content}\n"
                elif role == 'user':
                    conversation += f"User: {content}\n"
                elif role == 'assistant':
                    conversation += f"Assistant: {content}\n"
            texts.append(conversation)

        return tokenizer(texts, truncation=True, padding='max_length', max_length=512)

    # Split dataset
    test_size = config['dataset']['test_split']
    split_dataset = dataset['train'].train_test_split(test_size=test_size)

    tokenized_datasets = DatasetDict({
        'train': split_dataset['train'].map(tokenize_function, batched=True, remove_columns=split_dataset['train'].column_names),
        'test': split_dataset['test'].map(tokenize_function, batched=True, remove_columns=split_dataset['test'].column_names),
    })

    return tokenized_datasets

def train_model(config, model, tokenizer, dataset):
    """Train the model."""
    training_args = TrainingArguments(
        output_dir=config['training']['output_dir'],
        num_train_epochs=config['training']['num_train_epochs'],
        per_device_train_batch_size=config['training']['per_device_train_batch_size'],
        per_device_eval_batch_size=config['training']['per_device_eval_batch_size'],
        gradient_accumulation_steps=config['training']['gradient_accumulation_steps'],
        learning_rate=float(config['training']['learning_rate']),
        warmup_steps=config['training']['warmup_steps'],
        logging_steps=config['training']['logging_steps'],
        save_steps=config['training']['save_steps'],
        eval_steps=config['training']['eval_steps'],
        save_total_limit=config['training']['save_total_limit'],
        load_best_model_at_end=config['training']['load_best_model_at_end'],
        metric_for_best_model=config['training']['metric_for_best_model'],
        greater_is_better=config['training']['greater_is_better'],
        eval_strategy="steps",
        save_strategy="steps",
        fp16=False,
        bf16=torch.cuda.is_available(),
        dataloader_pin_memory=False,
    )

    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer,
        mlm=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset['train'],
        eval_dataset=dataset['test'],
        data_collator=data_collator,
    )

    print("Starting training...")
    trainer.train()

    # Save the final model
    final_model_path = os.path.join(config['training']['output_dir'], "final_model")
    trainer.save_model(final_model_path)
    tokenizer.save_pretrained(final_model_path)

    return final_model_path

def export_to_gguf(config, model_path: Path) -> Optional[Path]:
    """Export model to GGUF format using llama.cpp."""
    final_model_path = Path(model_path)
    output_name = config['export']['output_name']
    gguf_path = Path(f"{output_name}.gguf").resolve()
    model_mtime = _latest_mtime_in_directory(final_model_path)

    if gguf_path.exists() and model_mtime and gguf_path.stat().st_mtime >= model_mtime:
        print(f"Existing GGUF file at {gguf_path} is up to date. Skipping conversion.")
        return gguf_path

    print("Exporting to GGUF format...")

    llama_cpp_path = Path(__file__).resolve().parents[1].parent / 'llama.cpp'
    convert_script = llama_cpp_path / 'convert_hf_to_gguf.py'

    if not convert_script.exists():
        print(f"Error: convert_hf_to_gguf.py not found at {convert_script}")
        return None

    aggregator = final_model_path / "model.safetensors"
    shards = list(final_model_path.glob("model-*.safetensors"))
    temp_aggregator: Optional[Path] = None

    try:
        if aggregator.exists() and shards:
            temp_aggregator = aggregator.with_name(f"{aggregator.name}.bak")
            counter = 0
            while temp_aggregator.exists():
                counter += 1
                temp_aggregator = aggregator.with_name(f"{aggregator.name}.bak{counter}")
            aggregator.rename(temp_aggregator)
            print("Temporarily hiding aggregated safetensors file to avoid duplicate tensor names.")

        result = subprocess.run(
            [
                sys.executable,
                str(convert_script),
                str(final_model_path),
                '--outtype', config['quantization']['method'],
                '--outfile', str(gguf_path),
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        print(f"GGUF exported to: {gguf_path}")
        if result.stdout:
            print("Conversion output:", result.stdout)
        if result.stderr:
            print("Conversion warnings:", result.stderr)
        return gguf_path
    except subprocess.CalledProcessError as e:
        print(f"Failed to export GGUF: {e}")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        return None
    finally:
        if temp_aggregator and temp_aggregator.exists() and not aggregator.exists():
            temp_aggregator.rename(aggregator)

def export_to_mlx(config, model_path):
    """Export model to MLX format for Mac."""
    print("Exporting to MLX format...")

    # This would require MLX library and conversion script
    # For now, just print a message
    print("MLX export not implemented yet. Please use Apple's MLX library.")

def main():
    config = load_config()

    dataset_path = _resolve_dataset_path(config)
    config['dataset']['path'] = str(dataset_path)

    output_dir = Path(config['training']['output_dir'])
    if not output_dir.is_absolute():
        config_dir = Path(config['_config_path']).parent
        output_dir = (config_dir / output_dir).resolve()
    else:
        output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    config['training']['output_dir'] = str(output_dir)

    final_model_dir = output_dir / "final_model"
    metadata_path = output_dir / "training_metadata.json"

    current_metadata = _build_training_metadata(config, dataset_path, final_model_dir)
    cached_metadata = _load_cached_metadata(metadata_path)
    metadata = dict(current_metadata)
    final_model_path: Optional[Path] = None
    reuse_trained_model = False
    reuse_reason = ""

    if cached_metadata and _metadata_matches(cached_metadata, current_metadata):
        reuse_trained_model = True
        reuse_reason = "No configuration or dataset changes detected"
        metadata = dict(cached_metadata)
        final_model_path = Path(metadata['final_model_path'])
    elif _final_model_is_complete(final_model_dir):
        model_mtime = _latest_mtime_in_directory(final_model_dir)
        if model_mtime and model_mtime >= current_metadata['dataset_mtime']:
            reuse_trained_model = True
            reuse_reason = "Found existing fine-tuned model newer than the dataset"
            final_model_path = final_model_dir.resolve()
            metadata = dict(current_metadata)
            metadata['final_model_path'] = str(final_model_path)
            _write_metadata(metadata_path, metadata)

    # Check platform
    system = platform.system().lower()
    if system == "linux":
        print("Running on Linux - will use CUDA if available")
    elif system == "darwin":
        print("Running on macOS - will use MPS if available")
    else:
        print(f"Running on {system} - platform-specific optimizations may not apply")

    if reuse_trained_model and reuse_reason:
        print(f"{reuse_reason}. Reusing previously trained model.")

    if not reuse_trained_model:
        # Setup model and tokenizer
        model, tokenizer = setup_model_and_tokenizer(config)

        # Load and prepare dataset
        dataset = load_and_prepare_dataset(config, tokenizer)

        # Train model
        final_model_path = Path(train_model(config, model, tokenizer, dataset)).resolve()
        metadata = dict(current_metadata)
        metadata['final_model_path'] = str(final_model_path)
        _write_metadata(metadata_path, metadata)

    # Export based on platform and config
    if config['export']['gguf']:
        gguf_path = export_to_gguf(config, final_model_path)
        if gguf_path:
            metadata['gguf_path'] = str(gguf_path)
            try:
                metadata['gguf_mtime'] = Path(gguf_path).stat().st_mtime
            except OSError:
                pass
            _write_metadata(metadata_path, metadata)

    if config['export']['mlx']:
        export_to_mlx(config, final_model_path)

    if reuse_trained_model:
        print("Reuse of existing model artifacts completed!")
    else:
        print("Training and export completed!")

if __name__ == "__main__":
    main()
