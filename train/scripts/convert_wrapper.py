#!/usr/bin/env python3
"""Wrapper to invoke the appropriate conversion script from a cloned llama.cpp repo.

Usage: scripts/convert_wrapper.py <llama_dir> <base_model> <model_dir> <output> <quant>
"""
import os
import sys
import subprocess


def run(cmd):
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd)


def main():
    if len(sys.argv) < 6:
        print("Usage: convert_wrapper.py <llama_dir> <base_model> <model_dir> <output> <quant>")
        sys.exit(2)

    llama_dir = sys.argv[1]
    base_model = sys.argv[2]
    model_dir = sys.argv[3]
    output = sys.argv[4]
    quant = sys.argv[5]

    # Prefer the HF-to-GGUF converter if present
    conv_hf = os.path.join(llama_dir, "convert_hf_to_gguf.py")
    conv_ggml = os.path.join(llama_dir, "convert_llama_ggml_to_gguf.py")
    conv_lora = os.path.join(llama_dir, "convert_lora_to_gguf.py")

    py = sys.executable

    if os.path.isfile(conv_hf):
        # If a local snapshot exists under model_dir (huggingface snapshot_download path), prefer that
        local_model_path = model_dir
        if os.path.isdir(model_dir):
            # detect HF snapshot layout: models--<user>--<repo>/snapshots/<rev>
            for entry in os.listdir(model_dir):
                if entry.startswith("models--"):
                    snaps = os.path.join(model_dir, entry, "snapshots")
                    if os.path.isdir(snaps):
                        snaps_list = sorted(os.listdir(snaps))
                        if snaps_list:
                            local_model_path = os.path.join(snaps, snaps_list[-1])
                            break

        if os.path.isdir(local_model_path):
            # run converter on local snapshot dir
            cmd = [py, conv_hf, local_model_path, "--outfile", output]
        else:
            # fallback to remote mode
            cmd = [py, conv_hf, "--remote", base_model, "--outfile", output]

        if quant and quant != "none":
            cmd += ["--outtype", quant]
        run(cmd)
        return

    if os.path.isfile(conv_ggml):
        # expects --input and --output
        cmd = [py, conv_ggml, "--input", model_dir, "--output", output]
        run(cmd)
        return

    if os.path.isfile(conv_lora):
        cmd = [py, conv_lora, "--outfile", output, model_dir]
        run(cmd)
        return

    print("No suitable converter found in", llama_dir)
    sys.exit(1)


if __name__ == '__main__':
    main()
