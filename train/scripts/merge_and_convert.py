#!/usr/bin/env python3
"""
Merge LoRA adapter with base model and convert to GGUF format
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base_model", required=True, help="HuggingFace base model ID")
    p.add_argument("--lora_adapter", required=True, help="Path to LoRA adapter")
    p.add_argument("--output_dir", required=True, help="Output directory for merged model")
    p.add_argument("--gguf_output", required=True, help="Output path for GGUF file")
    p.add_argument("--llama_cpp_dir", required=True, help="Path to llama.cpp directory")
    p.add_argument("--quantize", default="Q4_K_M", help="GGUF quantization type (default: Q4_K_M)")
    args = p.parse_args()

    print(f"\n{'='*60}")
    print("Merging LoRA adapter with base model...")
    print(f"{'='*60}\n")

    # Load base model
    print(f"Loading base model: {args.base_model}")
    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.bfloat16,
        device_map="cpu",  # Load to CPU for merging
        trust_remote_code=True,
    )

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    # Load LoRA adapter
    print(f"Loading LoRA adapter from: {args.lora_adapter}")
    model = PeftModel.from_pretrained(base_model, args.lora_adapter)

    # Merge adapter with base model
    print("Merging LoRA weights with base model...")
    merged_model = model.merge_and_unload()

    # Save merged model
    print(f"Saving merged model to: {args.output_dir}")
    os.makedirs(args.output_dir, exist_ok=True)
    merged_model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    print(f"\n{'='*60}")
    print("Converting to GGUF format...")
    print(f"{'='*60}\n")

    # Find the convert script
    convert_script = Path(args.llama_cpp_dir) / "convert_hf_to_gguf.py"
    if not convert_script.exists():
        print(f"ERROR: Converter script not found at {convert_script}")
        print("Please run 'make build_converter' first")
        sys.exit(1)

    # Convert to f16 GGUF first
    gguf_f16 = Path(args.gguf_output).with_suffix(".f16.gguf")
    print(f"Converting to f16 GGUF: {gguf_f16}")
    subprocess.run([
        sys.executable,
        str(convert_script),
        args.output_dir,
        "--outfile", str(gguf_f16),
        "--outtype", "f16",
    ], check=True)

    # Quantize if requested
    if args.quantize.lower() != "none" and args.quantize.lower() != "f16":
        quantize_bin = Path(args.llama_cpp_dir) / "build" / "bin" / "llama-quantize"
        if not quantize_bin.exists():
            print(f"WARNING: quantize binary not found at {quantize_bin}")
            print(f"Using f16 GGUF instead")
            os.rename(gguf_f16, args.gguf_output)
        else:
            print(f"Quantizing to {args.quantize}: {args.gguf_output}")
            subprocess.run([
                str(quantize_bin),
                str(gguf_f16),
                str(args.gguf_output),
                args.quantize,
            ], check=True)
            # Remove f16 file
            os.remove(gguf_f16)
    else:
        os.rename(gguf_f16, args.gguf_output)

    print(f"\n{'='*60}")
    print(f"✅ GGUF model saved to: {args.gguf_output}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
