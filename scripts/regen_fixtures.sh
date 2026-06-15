#!/usr/bin/env bash
# Regenerate every fixture's plan JSON deterministically and fully offline.
# Each examples/<fixture>/ has *.tf using a mock AWS provider (no account, no network at plan).
set -euo pipefail

export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"
mkdir -p "$TF_PLUGIN_CACHE_DIR"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/examples"

for dir in */; do
  [ -f "${dir}main.tf" ] || continue
  echo "==> ${dir%/}"
  (
    cd "$dir"
    terraform init -input=false -no-color >/dev/null
    terraform plan -input=false -no-color -out=plan.out >/dev/null
    terraform show -json plan.out > plan.tfplan.json
    rm -f plan.out
    rm -rf .terraform .terraform.lock.hcl
  )
done
echo "done — regenerated $(ls -d */ | wc -l | tr -d ' ') fixtures"
