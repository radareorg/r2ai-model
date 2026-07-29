#!/usr/bin/env python3
"""
Fine-tune LLMs using standard Transformers + PEFT (LoRA)
No Unsloth - just reliable, widely compatible training
"""
import argparse
import csv
import json
import os
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    TrainingArguments,
    Trainer,
)


def load_tsv_data(data_dir):
    """Load all TSV files from data_dir and subdirectories."""
    data_path = Path(data_dir)
    all_data = []

    # Find all .tsv files
    tsv_files = list(data_path.rglob("*.tsv"))

    # Skip files with .ignored or .ok extensions
    tsv_files = [f for f in tsv_files if not any(
        str(f).endswith(ext) for ext in [".tsv.ignored", ".tsv.ok"]
    )]

    print(f"Found {len(tsv_files)} TSV files")

    for tsv_file in tsv_files:
        print(f"Loading {tsv_file}")
        try:
            with open(tsv_file, 'r', encoding='utf-8') as f:
                # Try to detect if first line is a header
                first_line = f.readline().strip()
                f.seek(0)

                # Check if it has headers (lowercase check)
                has_header = any(h in first_line.lower() for h in ['question', 'command', 'description'])

                if has_header:
                    reader = csv.DictReader(f, delimiter='\t')
                else:
                    # No headers - assume: Category, Question, Command format
                    reader = csv.DictReader(f, delimiter='\t', fieldnames=['category', 'question', 'command'])

                for row in reader:
                    # Flexibly map columns
                    question = (row.get('Question') or row.get('question') or
                               row.get('description') or '').strip()
                    answer = (row.get('Command') or row.get('command') or
                             row.get('answer') or '').strip()
                    category = (row.get('Category') or row.get('category') or 'General').strip()

                    # Skip empty rows
                    if question and answer:
                        all_data.append({
                            'question': question,
                            'answer': answer,
                            'category': category
                        })
        except Exception as e:
            print(f"Warning: Failed to load {tsv_file}: {e}")

    print(f"Loaded {len(all_data)} training examples")
    return all_data


def format_prompt(example, tokenizer):
    """Format and tokenize a single example."""
    prompt = f"""Below is a question about radare2. Write a command that appropriately answers the question.

### Question:
{example['question']}

### Command:
{example['answer']}"""

    # Tokenize with dynamic padding (pads to longest in batch)
    result = tokenizer(
        prompt,
        truncation=True,
        max_length=tokenizer.model_max_length,
        padding=False,  # DataCollator will pad dynamically
    )
    result["labels"] = result["input_ids"].copy()
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base_model", required=True, help="HuggingFace model ID")
    p.add_argument("--data_dir", required=True, help="Directory containing TSV training data")
    p.add_argument("--output_dir", required=True, help="Output directory for trained model")
    p.add_argument("--max_seq_length", type=int, default=2048, help="Maximum sequence length")
    p.add_argument("--load_in_4bit", action="store_true", default=True, help="Use 4-bit quantization")
    p.add_argument("--lora_r", type=int, default=16, help="LoRA rank")
    p.add_argument("--lora_alpha", type=int, default=16, help="LoRA alpha")
    p.add_argument("--lora_dropout", type=float, default=0, help="LoRA dropout")
    p.add_argument("--batch_size", type=int, default=2, help="Per-device training batch size")
    p.add_argument("--gradient_accumulation_steps", type=int, default=4, help="Gradient accumulation steps")
    p.add_argument("--learning_rate", type=float, default=2e-4, help="Learning rate")
    p.add_argument("--num_train_epochs", type=int, default=1, help="Number of training epochs")
    p.add_argument("--max_steps", type=int, default=-1, help="Max training steps (overrides epochs if set)")
    args = p.parse_args()

    # Load data
    data = load_tsv_data(args.data_dir)
    if not data:
        print("ERROR: No training data found!")
        return

    # Load tokenizer
    print(f"Loading tokenizer: {args.base_model}")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    tokenizer.model_max_length = args.max_seq_length

    # Prepare dataset
    print("Preparing dataset")
    dataset = Dataset.from_list(data)
    dataset = dataset.map(
        lambda x: format_prompt(x, tokenizer),
        remove_columns=dataset.column_names,
        num_proc=4,
    )

    # Load model in bf16 (no quantization - you have enough VRAM!)
    print(f"Loading model: {args.base_model}")

    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
    )

    # Enable gradient checkpointing to save memory
    model.gradient_checkpointing_enable()

    # Configure LoRA
    print(f"Configuring LoRA (r={args.lora_r}, alpha={args.lora_alpha})")
    peft_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )

    model = get_peft_model(model, peft_config)
    model.print_trainable_parameters()

    # Training arguments
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        num_train_epochs=args.num_train_epochs,
        max_steps=args.max_steps,
        learning_rate=args.learning_rate,
        bf16=True,
        logging_steps=10,
        save_strategy="steps",
        save_steps=500,  # Save checkpoint every 500 steps
        save_total_limit=1,  # Only keep the latest checkpoint
        optim="adamw_torch",
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        report_to="none",
        # Multi-GPU DDP settings
        ddp_find_unused_parameters=False,
        dataloader_pin_memory=True,
        dataloader_num_workers=4,  # Parallel data loading to saturate GPUs
    )

    # Data collator for padding
    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding=True,
    )

    # Trainer
    print("Starting training")
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        data_collator=data_collator,
    )

    trainer.train()

    # Save LoRA adapter
    print(f"Saving LoRA adapter to {args.output_dir}")
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    # Save metadata
    metadata = {
        "base_model": args.base_model,
        "lora_r": args.lora_r,
        "lora_alpha": args.lora_alpha,
        "num_examples": len(data),
        "num_epochs": args.num_train_epochs,
    }
    with open(f"{args.output_dir}/training_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "="*60)
    print("Testing model with inference examples...")
    print("="*60 + "\n")

    # Test inference on a few examples
    model.eval()
    test_questions = [
        "How do I analyze a function?",
        "How do I set a breakpoint?",
        "How do I print function names?",
    ]

    for question in test_questions:
        prompt = f"""Below is a question about radare2. Write a command that appropriately answers the question.

### Question:
{question}

### Command:
"""
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=64,
                temperature=0.7,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id,
            )
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        # Extract just the command part
        if "### Command:" in response:
            command = response.split("### Command:")[-1].strip()
        else:
            command = response
        print(f"Q: {question}")
        print(f"A: {command}\n")

    print("Training complete!")


if __name__ == "__main__":
    main()
