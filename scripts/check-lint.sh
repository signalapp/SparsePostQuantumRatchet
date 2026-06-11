#!/usr/bin/env bash
set -euo pipefail

echo "=== Build warning check ==="
lake build --no-ansi 2>&1 | tee /tmp/lake-build.log
if grep 'warning:' /tmp/lake-build.log | grep -qv 'declaration uses .sorry'; then
  echo "FAIL: non-sorry warnings found:"
  grep 'warning:' /tmp/lake-build.log | grep -v 'declaration uses .sorry'
  exit 1
fi
echo "PASS"

echo "=== Lint check ==="
lake exe runLinter Spqr 2>&1 | tee /tmp/lake-lint.log || true
if grep -q 'error:' /tmp/lake-lint.log; then
  echo "FAIL: lint errors in hand-written code:"
  grep 'error:' /tmp/lake-lint.log
  exit 1
fi
echo "PASS"
