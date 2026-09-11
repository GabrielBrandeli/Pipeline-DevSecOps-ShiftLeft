#!/usr/bin/env bash
docker info >/dev/null 2>&1 && echo "OK docker" || echo "FALHA: abra o Docker Desktop"
[ -d .venv ] && source .venv/bin/activate && echo "OK venv: $(python --version)"
echo "--- submodulos ---"
git submodule status
echo "--- git ---"
git status --short --branch
