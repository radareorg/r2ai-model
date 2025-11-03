#!/usr/bin/env python3
"""
Fine-tuning script for Radare2 AI Model

This script fine-tunes a configurable Hugging Face model on the Radare2 dataset
and exports it to GGUF format (Linux/NVIDIA) or MLX format (Mac).
"""

import os
import sys
import yaml
import torch
import platform
from pathlib import Path
from datasets import load_dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
import subprocess
import shutil

def load_config(config_path: str = "config.yaml"):
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

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
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
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
    dataset_path = config['dataset']['path']

    print(f"Loading dataset from: {dataset_path}")

    # Load JSONL dataset
    dataset = load_dataset('json', data_files=dataset_path)

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
        fp16=torch.cuda.is_available(),
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

def export_to_gguf(config, model_path):
    """Export model to GGUF format using llama.cpp."""
    print("Exporting to GGUF format...")

    # Convert to GGUF using llama.cpp's convert.py
    # This requires llama.cpp to be installed
    output_name = config['export']['output_name']
    gguf_path = f"{output_name}.gguf"

    # First, convert to HF format if needed
    convert_script = """
import sys
sys.path.insert(0, 'llama.cpp')
from convert_hf_to_gguf import main as convert_main

if __name__ == "__main__":
    import sys
    sys.argv = ['convert.py', '--model', '{model_path}', '--outtype', '{quantization}', '--outfile', '{gguf_path}']
    convert_main()
""".format(
        model_path=model_path,
        quantization=config['quantization']['method'],
        gguf_path=gguf_path
    )

    with open('convert_temp.py', 'w') as f:
        f.write(convert_script)

    try:
        subprocess.run([sys.executable, 'convert_temp.py'], check=True)
        print(f"GGUF exported to: {gguf_path}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to export GGUF: {e}")
    finally:
        os.remove('convert_temp.py')

def export_to_mlx(config, model_path):
    """Export model to MLX format for Mac."""
    print("Exporting to MLX format...")

    # This would require MLX library and conversion script
    # For now, just print a message
    print("MLX export not implemented yet. Please use Apple's MLX library.")

def main():
    config = load_config()

    # Check platform
    system = platform.system().lower()
    if system == "linux":
        print("Running on Linux - will use CUDA if available")
    elif system == "darwin":
        print("Running on macOS - will use MPS if available")
    else:
        print(f"Running on {system} - platform-specific optimizations may not apply")

    # Setup model and tokenizer
    model, tokenizer = setup_model_and_tokenizer(config)

    # Load and prepare dataset
    dataset = load_and_prepare_dataset(config, tokenizer)

    # Train model
    final_model_path = train_model(config, model, tokenizer, dataset)

    # Export based on platform and config
    if config['export']['gguf']:
        export_to_gguf(config, final_model_path)

    if config['export']['mlx']:
        export_to_mlx(config, final_model_path)

    print("Training and export completed!")

if __name__ == "__main__":
    main()