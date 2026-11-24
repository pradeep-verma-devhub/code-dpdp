#!/usr/bin/env bash
# ==============================================================================
# code-dpdp CLI Launcher
# Automated Compliance Scanner for India's DPDP Act 2023 & DPDP Rules 2025
# ==============================================================================

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT_DIR/bin/code-dpdp" "$@"
