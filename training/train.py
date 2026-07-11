#!/usr/bin/env python3
"""
Fine-tuning script for Radare2 AI Model

This script fine-tunes a configurable Hugging Face model on the Radare2 dataset
and exports it to GGUF format (Linux/NVIDIA) or MLX format (Mac).
"""

import argparse
import copy
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
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
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


def common_prefix_length(left: str, right: str) -> int:
    length = 0
    while length < min(len(left), len(right)) and left[length] == right[length]:
        length += 1
    return length


def token_aligned_prefix_length(tokenizer, text: str, character_limit: int) -> int:
    encoded = tokenizer(
        text,
        add_special_tokens=False,
        return_offsets_mapping=True,
    )
    return max(
        (
            end
            for start, end in encoded["offset_mapping"]
            if end > start and end <= character_limit
        ),
        default=0,
    )


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
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
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

        without_assistant = copy.deepcopy(messages)
        without_assistant[index]["role"] = "__masked_assistant__"
        omitted = tokenizer.apply_chat_template(
            without_assistant,
            tokenize=False,
            add_generation_prompt=False,
            **template_kwargs,
        )
        prefix = common_prefix_length(rendered, omitted)
        suffix = 0
        suffix_limit = min(len(rendered), len(omitted))
        while suffix < suffix_limit:
            if rendered[-1 - suffix] != omitted[-1 - suffix]:
                break
            suffix += 1

        context = messages[:index]
        context_text = tokenizer.apply_chat_template(
            context,
            tokenize=False,
            add_generation_prompt=False,
            **template_kwargs,
        )
        generation_prompt = tokenizer.apply_chat_template(
            messages[:index],
            tokenize=False,
            add_generation_prompt=True,
            **template_kwargs,
        )
        if not generation_prompt.startswith(context_text):
            raise ValueError("Chat template generation prompt is not append-only")
        prompt_suffix = generation_prompt[len(context_text):]

        removed_length = len(rendered) - len(omitted)
        earliest = max(0, len(omitted) - suffix)
        candidates = []
        for candidate_start in range(earliest, prefix + 1):
            candidate_end = candidate_start + removed_length
            if rendered[:candidate_start] + rendered[candidate_end:] != omitted:
                continue
            assistant_block = rendered[candidate_start:candidate_end]
            raw_prompt_length = common_prefix_length(prompt_suffix, assistant_block)
            prompt_length = token_aligned_prefix_length(
                tokenizer,
                assistant_block,
                raw_prompt_length,
            )
            candidates.append((raw_prompt_length, prompt_length, candidate_start))
        if not candidates:
            raise ValueError("Chat template cannot isolate an assistant turn")
        _, prompt_length, start = max(
            candidates,
            key=lambda item: (item[0], -item[2]),
        )
        end = start + removed_length
        spans.append((start + prompt_length, end))

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

    def tokenize_function(examples):
        tools = examples.get("tools")
        rows = [
            tokenize_chat(
                tokenizer,
                messages,
                max_length,
                tools[index] if tools else None,
            )
            for index, messages in enumerate(examples['messages'])
        ]
        return {
            name: [row[name] for row in rows]
            for name in ("input_ids", "attention_mask", "labels")
        }

    test_size = float(config['dataset']['test_split'])
    split_seed = int(config['dataset'].get('split_seed', DEFAULT_SPLIT_SEED))
    split_dataset = group_train_test_split(dataset['train'], test_size, split_seed)

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

def parse_args():
    parser = argparse.ArgumentParser(description="Fine-tune a radare2 model from a YAML config.")
    parser.add_argument(
        "--config",
        default=os.environ.get("TRAIN_CONFIG", "config.yaml"),
        help="Training config path, relative to the training directory by default.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_config(args.config)

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
