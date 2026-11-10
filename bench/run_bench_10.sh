#!/bin/bash
# Re-runs the n = 8 benchmark 10 times per parameter set, pinned to one core,
# and appends everything to bench/results/bench.log (used for mean +- sd).
cd "$(dirname "$0")/.."
make -s >/dev/null
out=bench/results/bench.log
for mode in 2 3 5; do
  for r in $(seq 1 10); do
    echo "### mode=$mode run=$r $(date +%T)" >> "$out"
    taskset -c 0 ./build/bench_mobs$mode 8 >> "$out" 2>&1
  done
done
python3 bench/stats.py "$out"
