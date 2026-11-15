#!/bin/bash
# MOBS benchmark run natively on macOS (Apple silicon): 10 runs per parameter set
# and thread count (n = 8), plus one peak-memory run per parameter set (1 thread).
# macOS has no taskset, so the 1-thread runs are not pinned to a core.
# usage (from the repo root):  THREADS="1 4" CC=gcc-15 bench/run_bench_10_macos.sh [log]
cd "$(dirname "$0")/.."
out=${1:-bench/results/bench-m2-macos.log}
mkdir -p "$(dirname "$out")"
{ echo "# $(date -u) $(uname -srm) $(sysctl -n machdep.cpu.brand_string) ncpu=$(sysctl -n hw.ncpu)" \
       "pcores=$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null) mem=$(( $(sysctl -n hw.memsize) / 1073741824 ))GiB"
  echo "# $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  echo "# $(${CC:-cc} --version | head -1)"; } >> "$out"
for mode in 2 3 5; do
  echo "### mem mode=$mode T=1 $(date +%T)" >> "$out"
  OMP_NUM_THREADS=1 /usr/bin/time -l ./build/bench_mobs$mode 8 2>&1 \
    | grep -E 'maximum resident set size|peak memory footprint' >> "$out"
  for T in ${THREADS:-1 4}; do
    for r in $(seq 1 10); do
      echo "### mode=$mode run=$r T=$T $(date +%T)" >> "$out"
      OMP_NUM_THREADS=$T ./build/bench_mobs$mode 8 >> "$out" 2>&1
    done
  done
done
echo "### DONE $(date +%T)" >> "$out"
