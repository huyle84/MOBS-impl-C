# Reproducing the measurements of the manuscript

This file maps every measured number in the manuscript (Computer Standards &
Interfaces submission, version `MOBS-CSI-23-11-2026-v2`) to the command and the
log that produced it. All logs are in `bench/results/`. Opening sizes and
constraint counts are deterministic; times depend on the machine.

## Machines

| Name in the paper | Machine | Compiler and flags | Thread pinning |
|---|---|---|---|
| Xeon | Ubuntu 24.04 VM, 2 vCPUs, "Intel Xeon Processor @ 2.10 GHz" | GCC 13.3, `-O2 -fopenmp` | 1 thread: `taskset -c 0` |
| Apple M2 | Mac mini M2 (4 performance + 4 efficiency cores, 16 GB), macOS 26.2, native | Homebrew GCC 16.2, `-O2 -fopenmp` | none (macOS has no pinning) |

## Build and test

```sh
make -j8                 # OPENMP=1 by default; on macOS: make CC=gcc-16
make check               # functional tests, including the (O8a) boundary tests
```

## Table 5 (costs of the implementation)

| Rows | Command | Log | Summary |
|---|---|---|---|
| Open / Vrfy, Xeon, 1 and 2 threads; issuance times on the Xeon | `make bench-mt THREADS="1 2"` (runs `bench/run_bench_10_threads.sh`) | `bench-xeon-2026-11-15.log` | `python3 bench/stats_threads.py <log>` |
| Open / Vrfy, Apple M2, 1 and 4 threads; issuance times on the M2 | `THREADS="1 4" CC=gcc-16 bench/run_bench_10_macos.sh <log>` | `bench-m2-macos-2026-11-15.log` | `python3 bench/stats_threads.py <log>` |
| Peak memory, Apple M2 | same run (one extra run per parameter set with `/usr/bin/time -l`) | `bench-m2-macos-2026-11-15.log` | `awk -f bench/mobs_mem.awk <log>` |
| Peak memory, Xeon | `for m in 2 3 5; do OMP_NUM_THREADS=1 /usr/bin/time -v ./build/bench_mobs$m 8 2>&1 \| grep "Maximum resident"; done` | (printed, KiB) | divide by 1048576 for GiB |
| Constraint counts, share of Keccak, opening size | `./build/bench_mobs2 8`, `./build/bench_mobs3 8`, `./build/bench_mobs5 8` | any of the logs above | deterministic |

Each script runs 10 times per parameter set and thread count with n = 8,
opening every other position. "Open" and "Verify" in the summary are circuit
construction plus proving or verification, in seconds. Issuance times are means
over 200 iterations per run, then over the 10 runs.

## Scaling with n (Section 4.5, paragraph "Scaling")

```sh
./build/bench_mobs2 1 4 16 32 64 128 256
```

The permutation counts, multiplication constraints and opening sizes printed
are deterministic and match the paper.

## Table 6 (same-machine comparison with [BB26])

Code of [BB26]: `blind_mldsa` and `swanky` as published by the authors. Copy
`bench/bb26/oneshot.rs` to `blind_mldsa/examples/`, then:

```sh
RUSTUP_TOOLCHAIN=stable cargo build --release --example oneshot      # Rust 1.97
B=./target/release/examples/oneshot
for T in 1 4; do echo "# RAYON_NUM_THREADS=$T masked"; RAYON_NUM_THREADS=$T $B 10 masked; done
echo "# RAYON_NUM_THREADS=1 hashed"; RAYON_NUM_THREADS=1 $B 10 hashed
awk -f bench/bb26/bb26_stats.awk <log>
```

| Rows | Log |
|---|---|
| [BB26] on the Apple M2, 1 and 4 threads, Masked and Hashed | `bb26-m2-2026-11-15.log` |
| [BB26] on the Xeon, 1 and 2 threads, Masked and Hashed | `bb26-xeon-2026-11-15.log` |

The ratios in Table 6 divide the MOBS times for ML-DSA-44 (Table 5) by the
[BB26] times on the same machine and with the same number of threads.

## Logs not used in the paper

`bench-2026-11-11.log` (single-threaded build before OpenMP),
`bench-2026-11-11-apple.log` and `bench-m2-2026-11-15.log` (Linux virtual
machines on Apple hardware) are kept for reference only.
