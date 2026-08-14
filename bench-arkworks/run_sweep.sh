#!/usr/bin/env bash
# Sweep constraint counts x thread counts. Each invocation is a fresh process so
# peak RSS (VmHWM) is per-configuration.
set -u

BIN="${BIN:-./target/release/bench-arkworks}"
OUT="${OUT:-results.jsonl}"
TRACE_DIR="${TRACE_DIR:-traces}"
SHAPES="${SHAPES:-mul}"
SIZES="${SIZES:-20 21 22}"
THREADS="${THREADS:-1 2 4 8 16}"
LABEL="${LABEL:-base}"

mkdir -p "$TRACE_DIR"

for shape in $SHAPES; do
  for n in $SIZES; do
    for t in $THREADS; do
      echo ">>> $LABEL shape=$shape log2n=$n threads=$t" >&2
      trace="$TRACE_DIR/${LABEL}_${shape}_${n}_${t}.trace"
      if RAYON_NUM_THREADS=$t "$BIN" "$shape" "$n" "$LABEL" >"$trace.out" 2>"$trace"; then
        grep RESULT_JSON "$trace.out" >>"$OUT"
      else
        code=$?
        echo "FAILED_JSON {\"shape\":\"$shape\",\"param\":$((1<<n)),\"label\":\"$LABEL\",\"threads\":$t,\"exit\":$code}" >>"$OUT"
        echo "!!! failed exit=$code (see $trace)" >&2
      fi
    done
  done
done
