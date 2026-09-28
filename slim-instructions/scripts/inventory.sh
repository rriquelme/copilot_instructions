#!/usr/bin/env bash
# Inventory of instruction files in the current repo with token estimates.
# Estimate: words * 1.35 (markdown prose averages ~1.3-1.4 tokens per word).
set -u
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root" || exit 1
printf '%-8s %6s %6s %7s  %s\n' TIER LINES WORDS TOKENS FILE
total=0
report() {
  local tier="$1" f="$2"
  [ -f "$f" ] || return
  local l w t
  l=$(wc -l < "$f"); w=$(wc -w < "$f"); t=$(( w * 135 / 100 ))
  printf '%-8s %6d %6d %7d  %s\n' "$tier" "$l" "$w" "$t" "$f"
  [ "$tier" = core ] && total=$(( total + t ))
}
report core .github/copilot-instructions.md
for f in AGENTS.md CLAUDE.md GEMINI.md; do report core "$f"; done
while IFS= read -r f; do report path "$f"; done < <(find .github/instructions -name '*.instructions.md' 2>/dev/null)
while IFS= read -r f; do report skill "$f"; done < <(find .github/skills .claude/skills .agents/skills -name 'SKILL.md' 2>/dev/null)
echo
echo "Always-on (core) estimated tokens per turn: $total"
echo
echo "Global files (read-only, used for dedupe):"
for g in "$HOME/.copilot/copilot-instructions.md"; do
  [ -f "$g" ] && echo "  present: $g ($(wc -l < "$g") lines)" || echo "  absent:  $g"
done
ls -d "$HOME"/.copilot/skills/*/ 2>/dev/null | sed 's/^/  skill:   /' || true
