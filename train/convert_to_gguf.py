#!/usr/bin/env python3
"""
Minimal conversion script that creates a placeholder .gguf file from a checkpoint.

This is only a lightweight demo so the Makefile flow can run without external
conversion tools. Replace this script with a proper converter for real models.
"""
import argparse
from pathlib import Path
import json


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input_dir", required=True)
    p.add_argument("--output_file", required=True)
    args = p.parse_args()

    inp = Path(args.input_dir)
    out = Path(args.output_file)
    if not inp.exists():
        print(f"Input directory {inp} does not exist")
        raise SystemExit(1)

    # Check for the dummy checkpoint we created in train.py
    ckpt = inp / "pytorch_model.bin"
    meta = inp / "metadata.json"
    if not ckpt.exists() or not meta.exists():
        print(f"Expected checkpoint/metadata not found in {inp}")
        raise SystemExit(1)

    # Read metadata for a tiny header
    header = json.loads(meta.read_text())

    # Write a small .gguf placeholder file
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        f.write(b"GGUF_PLACEHOLDER\n")
        f.write(b"base_model: ")
        f.write(header.get("base_model", "unknown").encode())
        f.write(b"\n")
        f.write(b"note: This is a placeholder .gguf created by convert_to_gguf.py\n")

    print(f"Wrote placeholder GGUF to {out}")


if __name__ == "__main__":
    main()

