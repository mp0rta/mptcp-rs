#!/usr/bin/env bash
# Interop Suite host entry (amendment §5.1): build the image, run the suite (or, with --probe, the
# Linux behaviour probe) inside it. Build the release client first.
# Usage: run.sh [--case NAME]... [--runs N] [--ci] | run.sh --probe
set -euo pipefail
cd "$(dirname "$0")/../../.."
script=run_suite.py
[ "${1:-}" != --probe ] || { script=probe.py; shift; }
docker build -q -t mptcp-rs-m1-test:local tests/interop >/dev/null
exec docker run --rm --init --network none --privileged -v "$PWD":/w -w /w mptcp-rs-m1-test:local python3 "tests/interop/suite/$script" "$@"
