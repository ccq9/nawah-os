#!/bin/sh
# unsafe policy (ADR-0002 item 6, after Sol OS ADR-008): the `unsafe` keyword only in the allowed
# modules, `asm!`/`global_asm!` only under kernel/src/arch/ and kernel/src/boot/, and the number of
# code lines containing `unsafe` must equal tools/unsafe-baseline.txt (a change needs an ADR).
# Comment lines (// and //!) are ignored; the lint names unsafe_code/unsafe_op_in_unsafe_fn do not match \bunsafe\b.
set -eu
cd "$(dirname "$0")/.."
ALLOWED='kernel/src/arch/|kernel/src/boot/|kernel/src/mm/|kernel/src/cell.rs|kernel/src/bootinfo.rs'
status=0
total=0
for f in $(find kernel/src -name '*.rs' | sort); do
  n=$(grep -vE '^\s*//' "$f" | grep -cE '\bunsafe\b' || true)
  total=$((total + n))
  if [ "$n" != "0" ] && ! echo "$f" | grep -qE "$ALLOWED"; then echo "unsafe outside allowed modules: $f ($n lines)"; status=1; fi
  a=$(grep -vE '^\s*//' "$f" | grep -cE '\b(global_asm|asm)!' || true)
  if [ "$a" != "0" ] && ! echo "$f" | grep -qE 'kernel/src/arch/|kernel/src/boot/'; then echo "asm outside arch/boot: $f"; status=1; fi
done
baseline=$(cat tools/unsafe-baseline.txt)
echo "unsafe lines: $total (baseline $baseline)"
if [ "$total" != "$baseline" ]; then echo "unsafe line count changed; update tools/unsafe-baseline.txt with an ADR"; status=1; fi
exit $status
