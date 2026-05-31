#!/bin/bash
# wtfpkg-scan.sh — Run all wtfpkg YARA rules against a target path
#
# Usage:
#   ./wtfpkg-scan.sh /path/to/scan
#   ./wtfpkg-scan.sh /path/to/package.whl
#   ./wtfpkg-scan.sh /path/to/gem-archive.gem
#
# Output: matching rule name, file, and metadata

set -euo pipefail

RULES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target_path_or_file>" >&2
    exit 1
fi

RULE_FILES=(
    "$RULES_DIR/wtfpkg_apt.yar"
    "$RULES_DIR/wtfpkg_cargo.yar"
    "$RULES_DIR/wtfpkg_gem.yar"
    "$RULES_DIR/wtfpkg_npm.yar"
    "$RULES_DIR/wtfpkg_pip.yar"
)

for f in "${RULE_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "Missing rule file: $f" >&2
        exit 1
    fi
done

yara -r "${RULE_FILES[@]}" "$TARGET"
