#!/usr/bin/env bash
R=$(cd "$(dirname "$0")" && pwd)
cd "$R" || exit 1
run() {
  KC_P=$1 nix shell nixpkgs#python3 -c python3 -I "$R/p2_fuzz.py" "$R" "$2" "$3" "$4" "$5" > "$R/fuzz-p$1-r$4.log" 2>&1 &
}
run 7 1500 1,2,4 1 11
run 7 400 1,2 2 12
run 11 1500 1,2,4 1 13
run 13 1000 2,4 2 14
run 31 800 1,2 2 15
run 101 400 2 3 16
wait
for f in "$R"/fuzz-p*.log; do echo "== $f"; cat "$f"; done
