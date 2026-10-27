#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks the public-repository content rules: SPDX headers on source files,
# and no em or en dashes or overclaiming wording in tracked text files.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0

files="$(git ls-files | grep -vE '(^|/)(go\.sum|LICENSE|CODE_OF_CONDUCT\.md)$|internal/cbom/schemacheck/schema/|\.json$' || true)"

hits="$(printf '%s\n' "$files" | xargs perl -CSD -ne 'print "$ARGV:$.: $_" if /[\x{2013}\x{2014}]/; close ARGV if eof' 2>/dev/null || true)"
if [ -n "$hits" ]; then echo "em or en dash:"; echo "$hits"; fail=1; fi

# The second grep removes the lines of this script that define the patterns.
hits="$(printf '%s\n' "$files" | xargs grep -nIiE 'quantum[- ](safe|proof|secure)|\bcompliant\b|\bcertified\b|world.?s first|\b(the|our|its) (first|only) (blockchain|chain|network|platform|tool|scanner)\b' 2>/dev/null | grep -v '^scripts/check-content.sh:' || true)"
if [ -n "$hits" ]; then echo "overclaiming wording:"; echo "$hits"; fail=1; fi

for f in $(printf '%s\n' "$files" | grep -E '\.(go|js|py|sol|sh|ya?ml)$|(^|/)Dockerfile$'); do
  head -n 3 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' || { echo "missing SPDX header: $f"; fail=1; }
done

exit "$fail"
