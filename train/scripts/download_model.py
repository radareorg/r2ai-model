#!/usr/bin/env python3
"""Download a Hugging Face repo snapshot to a local folder.

Usage: python3 scripts/download_model.py <repo_id> <cache_dir> <hf_token_or_NONE>
"""
import sys
from huggingface_hub import snapshot_download


def main():
    if len(sys.argv) < 3:
        print("Usage: download_model.py <repo_id> <cache_dir> <hf_token_or_NONE>")
        sys.exit(2)
    repo_id = sys.argv[1]
    cache_dir = sys.argv[2]
    token = None
    if len(sys.argv) > 3 and sys.argv[3] and sys.argv[3] != 'NONE':
        token = sys.argv[3]

    print(f"snapshot_download: {repo_id} -> {cache_dir}")
    snapshot_download(repo_id=repo_id, cache_dir=cache_dir, token=token)


if __name__ == '__main__':
    main()

