#!/usr/bin/env python3
"""
Minimal placeholder training script.

This script simulates training by creating an output directory and writing
a small checkpoint file and a metadata JSON. It accepts the arguments used
by the Makefile so you can run `make train` or call this directly.
"""
import argparse
import json
import os
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base_model", required=True)
    p.add_argument("--data_dir", required=True)
    p.add_argument("--output_dir", required=True)
    args = p.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Write a tiny dummy checkpoint file
    ckpt = out / "pytorch_model.bin"
    with ckpt.open("wb") as f:
        f.write(b"DUMMY_CHECKPOINT_FOR_BASE:" + args.base_model.encode())

    # Write metadata
    meta = {
        "base_model": args.base_model,
        "data_dir": args.data_dir,
        "note": "This is a placeholder checkpoint created by train.py for Makefile demo purposes."
    }
    with (out / "metadata.json").open("w") as f:
        json.dump(meta, f, indent=2)

    print(f"Wrote dummy checkpoint to {ckpt}")


if __name__ == "__main__":
    main()

