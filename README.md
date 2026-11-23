# MOBS[ML-DSA] — reference implementation in C

A complete implementation of **MOBS (Modular-Opening Blind Signatures)** as
described in the accompanying manuscript (version `MOBS-CSI-23-11-2026-v2`):

* **Unmodified ML-DSA (FIPS 204) signer.** Two-move blind issuance: the signer
  receives a 32/48/64-byte string `C = SHAKE256(DS_com‖r‖m)` and returns exactly
  one FIPS 204 signature on `DS_iss‖C`. No positions to be opened are agreed in
  advance.
* **Opening module.** From the base signature, the user opens **any set `D` of
  positions** of `m`, as often as it wants, bound to a context `ctx`. Openings
  cannot be linked to each other or to the signing session.
* **NIZK: Ligero** (AHIV17) over the Goldilocks field, made non-interactive with
  the BCS/Fiat–Shamir transform and cSHAKE256. It relies only on hash functions
  and needs no trusted setup. The proven relation is (O1)–(O8) of the
  manuscript. The security bounds are proven in the **classical ROM**
  (Appendix A of the manuscript); there is no proof in the QROM.

Language: **C (C11/gnu11)**, the language of the official ML-DSA reference
implementation (pq-crystals/dilithium, submitted to NIST) and of widely used
libraries (liboqs, PQClean, mldsa-native). The ML-DSA code is compiled
**unmodified** from `third_party/dilithium` (commit `d35ba3fe`, 3 June 2026,
FIPS 204 with context strings); the KAT hashes of all three parameter sets match
the published `SHA256SUMS`.

> This is a research prototype. It has **not been audited** and the prover is
> **not constant-time**. See `DESIGN.md` §5.

## 1. Why Ligero

The theorems of the manuscript need a labelled NIZK in the ROM with **zero
knowledge** (for blindness and multi-show unlinkability) and **online
simulation-extractability** (for OMUF-MO), and with no assumption other than
hash functions and ML-DSA itself (assumptions that are believed to hold against
quantum computers). The column "Online extraction" below refers to the
classical ROM.

| Candidate | Hash-only / no setup | Online extraction | Fit for the relation (~85 % Keccak) | Implementation effort | Proof size |
|---|---|---|---|---|---|
| **Ligero + BCS** (chosen) | yes / yes | yes, from the Merkle queries (straight-line); proven in Appendix A of the manuscript | good: generic R1CS-style circuit over a 64-bit field | low: RS code + NTT + Merkle | large (a few MiB) |
| VOLE-in-the-head (FAEST-style) | yes / yes | feasible (via RO queries) | very good for binary circuits | medium to high | smaller |
| Sumcheck/GKR + Ligero (Longfellow-zk) | yes / yes | feasible (via RO queries) | good, needs a layered circuit | high | smaller |
| STARK/FRI (AIR) | yes / yes | feasible (via RO queries) | must be rewritten as an AIR | high | small (succinct) |
| Lattice NIZK (LNP22, …) | yes / yes | usually needs rewinding | good for (O5), very expensive for SHAKE | high | depends strongly on the Keccak part |
| Groth16 / PLONK / Bulletproofs | **no** (pairings/DL) | — | — | — | very small |

Ligero is the best fit for a **self-contained, checkable reference
implementation**: minimal assumptions (hashing only, from the same Keccak family
as ML-DSA), statistical zero knowledge, the natural straight-line extraction of
BCS, standard building blocks, and no external dependencies. The price is a
larger proof than optimized systems (see §5). The circuit layer (`cs_t`) does not
depend on the proof system, so it can be moved to VOLEitH or Longfellow later.

## 2. Layout

```
src/
  field.[ch]           Goldilocks field p = 2^64 − 2^32 + 1, NTT, coset
  cs.[ch]              constraint system (multiplications x·y = z, linear constraints)
  gadgets.[ch]         bits, XOR, comparison with constants, bit decomposition
  keccak_circuit.[ch]  Keccak-f[1600] and SHAKE256 as circuits
  mldsa_circuit.[ch]   opening relation (O1)–(O8) of MOBS[ML-DSA]
  ligero.[ch]          Ligero prover/verifier (BCS, salted Merkle tree)
  xof.[ch]             cSHAKE256 (SP 800-185) for the random oracle of the NIZK
  mobs.[ch]            MOBS API: keygen, user1, sign, user2, open, verify
  mobs_params.h        constants, domain separation
tests/                 test_field, test_xof, test_keccak, test_ligero,
                       test_mldsa_circuit{2,3,5}, test_mobs{2,3,5}
examples/demo.c        full example: 6 attributes, two different openings
bench/                 benchmarks, scripts and raw logs (see REPRODUCE.md)
third_party/dilithium  unmodified ML-DSA reference code, CC0/Apache-2.0
DESIGN.md              byte-level specification, circuit design, parameters and security
REPRODUCE.md           how each number of the manuscript was produced
```

## 3. Build and test

Requirements: 64-bit GCC or Clang (`__int128` is needed), `make`, `libm`, and
OpenMP (`OPENMP=1` by default; `make OPENMP=0` builds a single-threaded
version). Tested on Ubuntu 24.04 with GCC 13.3 (x86-64) and on macOS 26.2 with
Homebrew GCC 16.2 (Apple M2). On Windows, use WSL2 (MSVC does not support
`__int128`).

```sh
make              # build for ML-DSA-44/65/87 (modes 2/3/5)
make check        # functional tests (end-to-end with small, INSECURE Ligero parameters)
make check-full   # end-to-end with real parameters, ML-DSA-44 (about 1 minute)
./build/test_mobs3 && ./build/test_mobs5   # real parameters for ML-DSA-65/87
./build/demo2     # example (add --fast for the small test parameters)
./build/bench_mobs2 4 8 16 32 64           # benchmark for several n
make bench-mt     # 10 runs per parameter set and thread count (Table 5)
```

Status: all of `make check` and the tests with real parameters pass for all
three parameter sets; builds with AddressSanitizer and UBSan are clean.

Main checks: the SHAKE256 circuit matches `fips202.c`; the in-circuit
SampleInBall matches `poly_challenge`; real FIPS 204 signatures satisfy the
circuit; a wrong disclosed value, a wrong public key, a forged hidden attribute
and a corrupted signature each violate a constraint; the (O8a) range check is
exact at the boundary (`z = ±(γ₁−β−1)` is accepted, `z = ±(γ₁−β)` is rejected);
a proof with any modified byte, a wrong label `ctx`, a wrong set `D` or a wrong
`pk` is rejected; full openings `D=[n]` and empty openings `D=∅` work.

## 4. API

```c
#include "mobs.h"   /* compile with -DDILITHIUM_MODE=2|3|5, link build/libmobsX.a -lm */

uint8_t pk[MOBS_PK_BYTES], sk[MOBS_SK_BYTES];
mobs_keygen(pk, sk);                                   /* issuer */

/* blind issuance: m holds n attributes of 32 bytes each */
mobs_user_state_t st; mobs_cred_t cred;
uint8_t rho1[MOBS_RHO1_BYTES], rho2[MOBS_RHO2_BYTES];
mobs_user1(&st, rho1, m, n);                           /* user -> signer: rho1 = C */
mobs_sign(rho2, rho1, sk);                             /* one standard ML-DSA.Sign */
if (mobs_user2(&cred, &st, rho2, pk) != 0) { /* invalid signature */ }

/* open any positions, at any time, any number of times */
uint8_t dmask[n] = {0}; dmask[3] = 1;                  /* open position 3 only */
uint8_t *tau; size_t taulen;
mobs_open(&tau, &taulen, &cred, pk, dmask, ctx, ctxlen, NULL);

/* verifier: knows only pk, n, D, y_D, ctx */
int ok = mobs_verify(pk, n, dmask, y, ctx, ctxlen, tau, taulen, NULL) == 0;
free(tau);
```

Return values: `0` means success. `mobs_user2` returns `-1` for an invalid
signature and `-2` if `SampleInBall` of the signature needs more blocks than
allowed (probability at most 2^−140 with an honest signer). `ctx` should contain
the verifier's identity and a nonce to prevent replay.

Names in the API and in the manuscript: `rho1` = `msg1` (= `C`), `rho2` = `msg2`
(the FIPS 204 signature), `tau` = the opening `θ`.

Message sizes: `rho1` = 32/48/64 bytes; `rho2` = 2420/3309/4627 bytes (a FIPS 204
signature); `pk` = 1312/1952/2592 bytes.

## 5. Measurements (the numbers used in the manuscript)

Every number in Tables 5–6 of the manuscript comes from the logs below;
`REPRODUCE.md` gives the commands. Setting: n = 8, every other position opened,
10 runs per parameter set and thread count; mean ± standard deviation
(`bench/stats_threads.py`).

* **Xeon**: Ubuntu 24.04 virtual machine, 2 vCPUs "Intel Xeon Processor @ 2.10 GHz",
  GCC 13.3 `-O2 -fopenmp`; single-threaded runs are pinned with `taskset -c 0`.
  Logs: `bench/results/bench-xeon-2026-11-15.log`, `bench/results/bb26-xeon-2026-11-15.log`.
* **Apple M2**: Mac mini M2 (4 performance + 4 efficiency cores, 16 GB),
  macOS 26.2, native, Homebrew GCC 16.2 `-O2 -fopenmp`; macOS has no core
  pinning. Logs: `bench/results/bench-m2-macos-2026-11-15.log`,
  `bench/results/bb26-m2-2026-11-15.log`.

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| KeyGen, Xeon / M2 (ms) | 0.10 / 0.047 | 0.18 / 0.088 | 0.25 / 0.129 |
| User₁, Xeon / M2 (ms) | 0.002 / 0.002 | 0.002 / 0.002 | 0.002 / 0.002 |
| Sign (FIPS 204), Xeon / M2 (ms) | 0.39 / 0.22 | 0.59 / 0.37 | 0.79 / 0.43 |
| User₂, Xeon / M2 (ms) | 0.10 / 0.052 | 0.14 / 0.085 | 0.29 / 0.138 |
| Open, Xeon, 1 thread (s) | 12.09 ± 0.55 | 18.84 ± 0.26 | 29.79 ± 0.92 |
| Open, Xeon, 2 threads (s) | 6.96 ± 0.33 | 10.69 ± 0.29 | 16.74 ± 0.60 |
| Open, M2, 1 thread (s) | 3.53 ± 0.03 | 5.00 ± 0.01 | 7.70 ± 0.02 |
| Open, M2, 4 threads (s) | 1.41 ± 0.01 | 1.98 ± 0.00 | 3.06 ± 0.06 |
| Verify, Xeon, 1 thread (s) | 7.22 ± 0.38 | 12.67 ± 0.61 | 21.58 ± 0.95 |
| Verify, Xeon, 2 threads (s) | 4.49 ± 0.17 | 7.92 ± 0.35 | 13.48 ± 0.35 |
| Verify, M2, 1 thread (s) | 2.07 ± 0.03 | 3.65 ± 0.00 | 6.34 ± 0.03 |
| Verify, M2, 4 threads (s) | 1.15 ± 0.00 | 2.06 ± 0.00 | 3.66 ± 0.03 |
| Peak memory, 1 thread, Xeon / M2 | 0.74 / 0.81 GiB | 0.77 / 0.91 GiB | 1.02 / 1.13 GiB |
| Opening size `τ` | 2.96 MiB | 4.83 MiB | 7.61 MiB |

Issuance times (KeyGen, User₁, Sign, User₂) are single-threaded means over 200
iterations per run. Constraint counts and opening sizes are deterministic.

**Comparison with [BB26] on the same machines** (ML-DSA-44, the configuration
of Table 4 of [BB26], Rust 1.97, `bench/bb26/oneshot.rs`, statistics with
`bench/bb26/bb26_stats.awk`):

| [BB26] | Sign₁ | Prove | Verify | Proof |
|---|---|---|---|---|
| M2, 1 thread | 241 ms | 897 ms | 545 ms | 1 011 909 B |
| M2, 4 threads | 235 ms | 896 ms | 542 ms | 1 011 909 B |
| M2, Hashed mode, 1 thread | ≈ 0 | 1167 ms | 558 ms | 1 037 509 B |
| Xeon, 1 thread | 832 ms | 1102 ms | 998 ms | 1 011 909 B |
| Xeon, 2 threads | 806 ms | 939 ms | 785 ms | 1 011 909 B |

### Older runs (not used in the manuscript)

* `bench/results/bench-2026-11-11.log`: Xeon, single-threaded build before OpenMP.
* `bench/results/bench-2026-11-11-apple.log`: Linux aarch64 virtual machine on a
  different Apple machine, which an earlier README described as "M4-series";
  not reproducible on the Mac mini M2 above.
* `bench/results/bench-m2-2026-11-15.log`: Linux aarch64 virtual machine
  (4 vCPUs, 3 GiB, GCC 11.4) on the Mac mini M2 above; about 2.4 times slower
  than native macOS.

## 6. Security parameters (details in `DESIGN.md` §3.3)

By default, λ of the NIZK equals λ of the ML-DSA parameter set (128/192/256):
K = 2^14 slots per row, Reed–Solomon code of rate 1/4 on n = 2^16 columns,
`t` = 428 / 641 / 855 opened columns, padding `t_pad` = 512 / 768 / 1024,
repetitions s_I/s_L/s_Q = 3/2/2, 4/3/3, 6/4/4, and 2λ-bit Merkle digests and
salts. Then `ε_rbr ≤ 2^−127.9 / 2^−191.9 / 2^−255.9`. This is a success probability
per Fiat–Shamir query in the classical ROM, not a security level in the sense
of the NIST categories. Known QROM bounds give only about λ/2 bits; to target
about 128 bits against quantum adversaries with ML-DSA-44, use
`mobs_set_ligero_params(lg_params_level(256))` (6.48 MiB openings, 1.7–2.1 times
slower). `lg_params_test()` is for tests only.

## 7. Mapping to the manuscript

| Manuscript | Code |
|---|---|
| Base scheme `B[Sig,Com]`, Com = SHAKE256(DS_com‖r‖m) (Section 3) | `mobs_user1`, `mobs_sign`, `mobs_user2` (`src/mobs.c`) |
| Module `M[B,NIZK]`: Open/Verify, label = ctx (Section 3) | `mobs_open`, `mobs_verify`, `stmt_digest` |
| Statement digest (Section 4.3) | `stmt_digest`: "MOBS" ‖ ps ‖ n ‖ 0x00 ‖ pk ‖ (b_i ‖ y_i) |
| (O1) opening `m_D = y` (Section 4.4) | `mldsa_circuit.c`, block "(O1)" |
| (O2) commitment, (O3) `μ`, (O7) `c̃` | Keccak circuit, blocks "(O2)", "(O3)", "(O7)" |
| (O4) SampleInBall_B | `sampleinball_circuit` |
| (O5) `Az − c t₁ 2^d`, (O6) UseHint/Decompose | block "(O5)+(O6)" |
| (O8) norm of `z` (bit decomposition plus upper check), weight of `h` | blocks "(O8a)", "(O8b)"; `bounded()` |
| Ligero/BCS, ZK and OSE (Section 4.5, Appendix A) | `ligero.c`, `xof.c` (cSHAKE256) |

## 8. Limitations

* The prover is not constant-time; openings must be computed on a trusted device.
* No predicates Φ(m) yet (for example, proving age ≥ 18 without opening the
  year of birth); the bit-decomposition gadgets needed for them exist.
* Attributes are 32 bytes each; at most 256 attributes (`MOBS_MAX_ATTRS`).
* Zero knowledge and OSE of exactly this Ligero/BCS variant are proven in the
  classical ROM (Proposition 7 and Appendix A of the manuscript). There is no
  proof in the QROM (`DESIGN.md` §3.5).
* The project code is MIT-licensed (see `LICENSE`); `third_party/dilithium`
  keeps its original license (CC0 or Apache-2.0).
