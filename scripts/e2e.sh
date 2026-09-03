#!/usr/bin/env bash
set -euo pipefail

python3 -m unittest discover -s simulator -p 'test_*.py' -v
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/check_determinism.py
python3 scripts/check_docs.py
python3 scripts/publication_check.py

mawk -f tools/rxown-summarize.awk /dev/null >/dev/null
cc -std=gnu11 -Wall -Wextra -Werror -fsyntax-only mitigations/gro-toggle.c

git apply --numstat patches/949-wifi-ath11k-use-private-page-frag-caches-for-rxdma.patch >/dev/null
git apply --numstat patches/950-wifi-ath11k-mark-private-rxfrag-validation-build.patch >/dev/null

printf '%s\n' 'public repository end-to-end checks passed'
