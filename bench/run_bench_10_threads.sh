#!/bin/bash
# 10 runs per parameter set and thread count (n = 8). T=1 is pinned to core 0.
# usage: THREADS="1 4" bench/run_bench_10_threads.sh [log]
cd "$(dirname "$0")/.."
out=${1:-bench/results/bench-threads.log}
{ echo "# $(date -u) $(uname -srm) nproc=$(nproc) $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"; gcc --version | head -1; } >> "$out"
for mode in 2 3 5; do
  for T in ${THREADS:-1 4}; do
    for r in $(seq 1 10); do
      echo "### mode=$mode run=$r T=$T $(date +%T)" >> "$out"
      if [ "$T" = 1 ]; then OMP_NUM_THREADS=1 taskset -c 0 ./build/bench_mobs$mode 8 >> "$out" 2>&1
      else OMP_NUM_THREADS=$T ./build/bench_mobs$mode 8 >> "$out" 2>&1; fi
    done
  done
done
echo "### DONE $(date +%T)" >> "$out"
