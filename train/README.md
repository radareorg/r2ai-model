# Getting a .gguf model using only `make`

This repository includes a `Makefile` that sets up a Python `venv`, installs dependencies, runs training, and converts a trained checkpoint into a `.gguf` file. The goal is to get a ready-to-use `.gguf` using only `make` commands.

Prerequisites
- Python 3 installed and accessible as `python3`.
- If you have a GPU, install the appropriate CUDA-enabled PyTorch inside the venv (see notes below).
- A training entrypoint `train.py` that accepts `--base_model`, `--data_dir`, and `--output_dir`, or edit the `train` target in `Makefile` to call your existing training command.
- A conversion script `convert_to_gguf.py` (or adapt the `convert` target to call your preferred converter like the `llama.cpp` conversion tool).

Quick one-line workflow (uses just `make`):

1. Create the venv and install dependencies:

```
make        # same as `make install` — creates ./venv and installs deps
```

2. Run training (example):

```
make train BASE_MODEL=facebook/llama-2-7b DATA_DIR=../data OUTPUT_DIR=./out
```

- Replace `BASE_MODEL` with the HF repo ID or local checkpoint you want to fine-tune.
- `DATA_DIR` should point to your dataset folder.
- `OUTPUT_DIR` is where checkpoints will be written.

3. Convert the trained checkpoint to `.gguf`:

```
make convert OUTPUT=./out/model.gguf OUTPUT_DIR=./out
```

- The `convert` target looks for a `convert_to_gguf.py` script by default; if you use another converter (for example, the `llama.cpp`/ggml conversion scripts), update the `convert` target in `Makefile` to call it.

Files referenced
- `Makefile:1` — contains the targets: `venv`, `install`, `train`, `convert`, `freeze-reqs`, `clean`.

Notes & troubleshooting
- If a `requirements.txt` file exists, `make install` will install from it. Otherwise the Makefile installs a set of common packages (`transformers`, `datasets`, `accelerate`, `peft`, `safetensors`, `sentencepiece`, `huggingface_hub`).
- Installing PyTorch with the correct CUDA support is environment-specific. After `make` you can activate the venv and install a CUDA-enabled PyTorch with the official instructions from https://pytorch.org/.
- If you don’t have `train.py` or `convert_to_gguf.py`, you can either add them to the repo or modify the `train`/`convert` targets in `Makefile` to call your tooling (for example, `accelerate launch train.py ...` or `python path/to/llama.cpp/convert.py ...`).
- The Makefile will print helpful messages if expected scripts are missing.

Want me to add a minimal `train.py` or a conversion wrapper that calls a known gguf converter? I can scaffold those next.

