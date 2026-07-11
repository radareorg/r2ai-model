#!/usr/bin/env python3
"""
Fine-tuning script for Radare2 AI Model

This script fine-tunes a configurable Hugging Face model on the Radare2 dataset
and exports it to GGUF format (Linux/NVIDIA) or MLX format (Mac).
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Optional

import torch
import yaml
from datasets import DatasetDict, load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

DEFAULT_MAX_LENGTH = 2048
DEFAULT_SPLIT_SEED = 42
PREPROCESSING_VERSION = 5


def normalize_split_text(value: str, *, words_only: bool = False) -> str:
    value = value.casefold()
    if words_only:
        value = re.sub(r"[^\w]+", " ", value)
    return " ".join(value.split())


def split_keys(row) -> set[str]:
    """Return equivalence keys used to keep related rows in one split."""
    keys = set()
    messages = row.get("messages") or []
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if role == "user" and isinstance(content, str) and content.strip():
            keys.add("user:" + normalize_split_text(content, words_only=True))
        if role != "assistant":
            continue
        if isinstance(content, str) and content.strip():
            keys.add("target:" + normalize_split_text(content))
        for call in message.get("tool_calls") or []:
            function = call.get("function") or call
            name = str(function.get("name") or "")
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = normalize_split_text(arguments)
            canonical = json.dumps(
                arguments,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            keys.add(f"tool:{name}:{canonical}")
            if (
                isinstance(arguments, dict)
                and isinstance(arguments.get("command"), str)
            ):
                keys.add(
                    "target:" + normalize_split_text(arguments["command"])
                )
    return keys


def group_train_test_split(dataset, test_size: float, seed: int) -> DatasetDict:
    """Split whole related-example components to prevent evaluation leakage."""
    row_count = len(dataset)
    if row_count < 2:
        raise ValueError("At least two rows are required for a train/test split")
    if not 0 < test_size < 1:
        raise ValueError("dataset.test_split must be between zero and one")

    parent = list(range(row_count))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    owners = {}
    keys_by_row = []
    for index, row in enumerate(dataset):
        keys = split_keys(row)
        if not keys:
            keys = {f"row:{index}"}
        keys_by_row.append(keys)
        for key in keys:
            previous = owners.setdefault(key, index)
            union(index, previous)

    components = {}
    component_keys = {}
    for index, keys in enumerate(keys_by_row):
        root = find(index)
        components.setdefault(root, []).append(index)
        component_keys.setdefault(root, set()).update(keys)

    ordered_groups = []
    for root, indices in components.items():
        signature = "\0".join(sorted(component_keys[root]))
        order = sha256(f"{seed}\0{signature}".encode("utf-8")).hexdigest()
        ordered_groups.append((order, indices))
    ordered_groups.sort()

    target_test_rows = max(1, round(row_count * test_size))
    test_indices = []
    train_indices = []
    for _, indices in ordered_groups:
        with_group = len(test_indices) + len(indices)
        current_distance = abs(target_test_rows - len(test_indices))
        new_distance = abs(target_test_rows - with_group)
        if len(test_indices) < target_test_rows and (
            with_group <= target_test_rows or new_distance < current_distance
        ):
            test_indices.extend(indices)
        else:
            train_indices.extend(indices)

    if not test_indices or not train_indices:
        raise ValueError("Group-aware split produced an empty train or test set")
    print(
        "Group-aware split: "
        f"{len(train_indices)} train rows, {len(test_indices)} test rows, "
        f"{len(components)} groups, seed {seed}"
    )
    return DatasetDict({
        "train": dataset.select(sorted(train_indices)),
        "test": dataset.select(sorted(test_indices)),
    })


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


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _build_training_metadata(config, dataset_path: Path, final_model_path: Path) -> dict:
    """Create a metadata snapshot to detect stale training artifacts."""
    dataset_stat = dataset_path.stat()
    relevant = {
        "preprocessing_version": PREPROCESSING_VERSION,
        "model": config.get("model"),
        "dataset": {
            "path": str(dataset_path),
            "test_split": config['dataset'].get('test_split'),
            "max_length": config['dataset'].get('max_length', DEFAULT_MAX_LENGTH),
            "split_seed": config['dataset'].get('split_seed', DEFAULT_SPLIT_SEED),
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
        "dataset_sha256": _file_sha256(dataset_path),
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
        "dataset_size",
        "config_fingerprint",
        "final_model_path",
    ]
    for key in required_keys:
        if cached.get(key) != current.get(key):
            return False
    cached_dataset_hash = cached.get("dataset_sha256")
    current_dataset_hash = current.get("dataset_sha256")
    if cached_dataset_hash and current_dataset_hash:
        if cached_dataset_hash != current_dataset_hash:
            return False
    elif cached.get("dataset_mtime") != current.get("dataset_mtime"):
        # Backward compatibility for metadata written before dataset hashes.
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


def _remove_model_weight_artifacts(path: Path) -> None:
    """Remove weight files from an earlier save without touching other output."""
    path.mkdir(parents=True, exist_ok=True)
    patterns = (
        "model*.safetensors",
        "model*.safetensors.index.json",
        "pytorch_model*.bin",
        "pytorch_model*.bin.index.json",
    )
    for pattern in patterns:
        for artifact in path.glob(pattern):
            artifact.unlink()


def _remove_stale_safetensors_index(path: Path) -> None:
    """Prefer a complete aggregate when an old shard index is inconsistent."""
    aggregator = path / "model.safetensors"
    index_path = path / "model.safetensors.index.json"
    if not aggregator.is_file() or not index_path.is_file():
        return

    try:
        index = json.loads(index_path.read_text())
        referenced = set(index.get("weight_map", {}).values())
    except (OSError, json.JSONDecodeError):
        referenced = set()
    missing = sorted(name for name in referenced if not (path / name).is_file())
    if referenced and not missing:
        return

    index_path.unlink()
    for shard in path.glob("model-*.safetensors"):
        shard.unlink()
    reason = "is invalid" if not referenced else f"references {len(missing)} missing shard(s)"
    print(f"Removed stale model.safetensors.index.json; it {reason}.")


def setup_tokenizer(config):
    """Load and validate the tokenizer required by the dataset pipeline."""
    model_name = config['model']['name']
    tokenizer_name = config['model'].get('tokenizer') or model_name

    print(f"Loading tokenizer: {tokenizer_name}")

    use_fast = bool(config.get('quantization', {}).get('use_fast_tokenizer', True))
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_name, use_fast=use_fast)
    if not tokenizer.is_fast:
        raise ValueError(
            "This training pipeline requires a fast tokenizer for exact assistant-only "
            "loss masking. Set quantization.use_fast_tokenizer=true and select a model "
            "with a fast tokenizer implementation."
        )
    if not tokenizer.chat_template:
        raise ValueError(
            f"Tokenizer {tokenizer_name} has no chat template. Select an instruct/chat "
            "checkpoint or explicitly configure a compatible tokenizer."
        )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


def setup_model_and_tokenizer(config):
    """Setup model and tokenizer based on config."""
    model_name = config['model']['name']
    tokenizer = setup_tokenizer(config)

    print(f"Loading model: {model_name}")

    cuda_available = torch.cuda.is_available()
    use_bf16 = cuda_available and torch.cuda.is_bf16_supported()
    model_dtype = (
        torch.bfloat16 if use_bf16
        else torch.float16 if cuda_available
        else torch.float32
    )

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        dtype=model_dtype,
    )

    # Apply LoRA if enabled
    if config.get('lora', {}).get('use_lora', False):
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

        lora_config = LoraConfig(
            r=config['lora']['r'],
            lora_alpha=config['lora']['lora_alpha'],
            target_modules=config['lora']['target_modules'],
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
        )
        if getattr(model, "is_loaded_in_4bit", False) or getattr(
            model, "is_loaded_in_8bit", False
        ):
            model = prepare_model_for_kbit_training(model)
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

    return model, tokenizer


def tokenize_chat(
    tokenizer,
    messages,
    max_length: int,
    tools=None,
) -> dict[str, list[int]]:
    """Tokenize a conversation and supervise only assistant turn bodies."""
    template_kwargs = {"tools": tools} if tools else {}
    rendered = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
        **template_kwargs,
    )
    spans = []
    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        generation_prompt = tokenizer.apply_chat_template(
            messages[:index],
            tokenize=False,
            add_generation_prompt=True,
            **template_kwargs,
        )
        completed_turn = tokenizer.apply_chat_template(
            messages[:index + 1],
            tokenize=False,
            add_generation_prompt=False,
            **template_kwargs,
        )
        if not completed_turn.startswith(generation_prompt):
            raise ValueError("Chat template assistant turn is not append-only")
        if not rendered.startswith(completed_turn):
            raise ValueError("Chat template conversation prefixes are not stable")
        if len(completed_turn) == len(generation_prompt):
            raise ValueError("Chat template rendered an empty assistant target")
        spans.append((len(generation_prompt), len(completed_turn)))

    if not spans:
        raise ValueError("Conversation has no assistant turn")

    encoded = tokenizer(
        rendered,
        add_special_tokens=False,
        truncation=True,
        max_length=max_length,
        return_offsets_mapping=True,
    )
    input_ids = encoded["input_ids"]
    labels = [-100] * len(input_ids)
    for position, (token_start, token_end) in enumerate(encoded["offset_mapping"]):
        if token_end <= token_start:
            continue
        if any(
            token_start >= span_start and token_end <= span_end
            for span_start, span_end in spans
        ):
            labels[position] = input_ids[position]
    if all(label == -100 for label in labels):
        raise ValueError(
            "No assistant tokens remain after truncation; increase dataset.max_length"
        )
    return {
        "input_ids": input_ids,
        "attention_mask": [1] * len(input_ids),
        "labels": labels,
    }


def load_and_prepare_dataset(config, tokenizer):
    """Load and prepare the dataset."""
    dataset_path = Path(config['dataset']['path'])
    max_length = int(config['dataset'].get('max_length', DEFAULT_MAX_LENGTH))
    if max_length <= 0:
        raise ValueError("dataset.max_length must be greater than zero")

    print(f"Loading dataset from: {dataset_path}")
    print(f"Maximum sequence length: {max_length}")

    # Load JSONL dataset
    dataset = load_dataset('json', data_files=str(dataset_path))

    def tokenize_function(examples, indices):
        tools = examples.get("tools")
        rows = []
        for index, messages in enumerate(examples['messages']):
            try:
                rows.append(tokenize_chat(
                    tokenizer,
                    messages,
                    max_length,
                    tools[index] if tools else None,
                ))
            except Exception as exc:
                raise ValueError(
                    f"Dataset row {indices[index]} is incompatible with the chat "
                    f"template from {tokenizer.name_or_path}: {exc}"
                ) from exc
        return {
            name: [row[name] for row in rows]
            for name in ("input_ids", "attention_mask", "labels")
        }

    test_size = float(config['dataset']['test_split'])
    split_seed = int(config['dataset'].get('split_seed', DEFAULT_SPLIT_SEED))
    split_dataset = group_train_test_split(dataset['train'], test_size, split_seed)

    tokenized_datasets = DatasetDict({
        'train': split_dataset['train'].map(tokenize_function, batched=True, with_indices=True, remove_columns=split_dataset['train'].column_names),
        'test': split_dataset['test'].map(tokenize_function, batched=True, with_indices=True, remove_columns=split_dataset['test'].column_names),
    })

    return tokenized_datasets

def train_model(config, model, tokenizer, dataset):
    """Train the model."""
    cuda_available = torch.cuda.is_available()
    use_bf16 = cuda_available and torch.cuda.is_bf16_supported()
    gradient_checkpointing = bool(
        config['training'].get('gradient_checkpointing', False)
    )
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
        fp16=cuda_available and not use_bf16,
        bf16=use_bf16,
        gradient_checkpointing=gradient_checkpointing,
        gradient_checkpointing_kwargs=(
            {"use_reentrant": False} if gradient_checkpointing else None
        ),
        dataloader_pin_memory=False,
    )

    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        padding=True,
        label_pad_token_id=-100,
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

    # Save a complete model for inference and GGUF conversion. PEFT's normal
    # save path contains only the adapter, so merge it into the base model first.
    final_model_path = os.path.join(config['training']['output_dir'], "final_model")
    if config.get('lora', {}).get('use_lora', False):
        adapter_path = os.path.join(config['training']['output_dir'], "adapter_model")
        trainer.save_model(adapter_path)
        tokenizer.save_pretrained(adapter_path)
        print(f"LoRA adapter saved to: {adapter_path}")
        merged_model = trainer.model.merge_and_unload()
        _remove_model_weight_artifacts(Path(final_model_path))
        merged_model.save_pretrained(final_model_path, safe_serialization=True)
        print(f"Merged inference model saved to: {final_model_path}")
    else:
        _remove_model_weight_artifacts(Path(final_model_path))
        trainer.save_model(final_model_path)
    tokenizer.save_pretrained(final_model_path)

    return final_model_path

def export_to_gguf(config, model_path: Path) -> Optional[Path]:
    """Export model to GGUF format using llama.cpp."""
    final_model_path = Path(model_path)
    output_name = Path(config['export']['output_name'])
    if not output_name.is_absolute():
        output_name = Path(config['_config_path']).parent / output_name
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

    _remove_stale_safetensors_index(final_model_path)
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

def parse_args():
    parser = argparse.ArgumentParser(description="Fine-tune a radare2 model from a YAML config.")
    parser.add_argument(
        "--config",
        default=os.environ.get("TRAIN_CONFIG", "config.yaml"),
        help="Training config path, relative to the training directory by default.",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="validate the dataset against the tokenizer chat template without loading model weights",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_config(args.config)

    dataset_path = _resolve_dataset_path(config)
    config['dataset']['path'] = str(dataset_path)

    if args.preflight:
        tokenizer = setup_tokenizer(config)
        dataset = load_and_prepare_dataset(config, tokenizer)
        print(
            f"Preflight passed: {len(dataset['train'])} train rows and "
            f"{len(dataset['test'])} test rows are compatible with "
            f"{tokenizer.name_or_path}."
        )
        return

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
        metadata = {**cached_metadata, **current_metadata}
        final_model_path = Path(metadata['final_model_path'])
    elif cached_metadata is None and _final_model_is_complete(final_model_dir):
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
        if not gguf_path:
            raise RuntimeError("GGUF export was requested but did not complete")
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
