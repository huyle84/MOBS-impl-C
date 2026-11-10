# MOBS[ML-DSA] — design and security notes

This document specifies exactly what the code computes and why the parameters
give the claimed security. It follows the manuscript
`MOBS-main-06-11-2026-v2.tex` (Sect. 5–6: base scheme `B[Sig,Com]`, module
`M[B,NIZK]`, opening relation (O1)–(O8)).

```
Π = M[ B[ML-DSA, Com_SHAKE256], NIZK_Ligero ]
```

## 1. Byte-level specification

Notation: `‖` is concatenation, `λ` is the NIST category of the ML-DSA parameter
set (128 / 192 / 256 for ML-DSA-44 / 65 / 87), `CT = λ/4` bytes is the FIPS 204
length of `c̃` (32 / 48 / 64).

| constant | value (16 bytes, zero padded) | role |
|---|---|---|
| `DS_com` | `"MOBS-v1/commit"` | commitment domain |
| `DS_iss` | `"MOBS-v1/issue"`  | prefix of the signed message |
| `ctx_ML` | `"MOBS-v1/ML-DSA"` | FIPS 204 context string |

Messages are vectors `m = (m_1,…,m_n)`, `1 ≤ n ≤ 256`, each `m_i ∈ {0,1}^256`
(32 bytes). Longer attributes should be hashed or encoded by the application.

**KeyGen** — `ML-DSA.KeyGen` (FIPS 204, Alg. 1), unmodified.

**User₁(m)** — `r ←$ {0,1}^{8·CT}`;
`C = SHAKE256(DS_com ‖ r ‖ m_1 ‖ … ‖ m_n, 8·CT bits)`; send `ρ₁ = C`.

**Sign(sk, ρ₁)** — `ρ₂ = ML-DSA.Sign(sk, DS_iss ‖ ρ₁, ctx_ML)` (FIPS 204, Alg. 2,
hedged, pure ML-DSA). This is the *only* signer operation; the signer learns
nothing but a uniformly looking `CT`-byte string.

**User₂(ρ₂)** — accept iff `ML-DSA.Verify(pk, DS_iss ‖ C, ρ₂, ctx_ML) = 1` and
`SampleInBall(c̃)` terminates within `B` SHAKE256 blocks (`B = 1` for
ML-DSA-44/65, `B = 2` for ML-DSA-87; see §3.4). The base signature is
`σ = (r, ρ₂)`; the credential is `(m, σ)`.

**Open(pk, m, σ, D, ctx)** — statement `x = (mode, n, pk, D, y_D = m_D)`, label
`ℓ = ctx`, witness `w = (m, r, c̃, z, h)`; output
`τ = Ligero.Prove(R_open, x, w, ℓ)`.

**Verify(pk, n, D, y_D, ctx, τ)** — `Ligero.Verify(R_open, x, τ, ℓ)`.

The statement is bound into Fiat–Shamir through
`dg = cSHAKE256("mode n" ‖ pk ‖ (b_i ‖ [y_i if b_i])_{i≤n}, 512, S = "MOBS-v1/stmt")`,
where `b_i = [i ∈ D]`; `dg` and `ctx` are absorbed (length-prefixed) into the
transcript before the commitment root.

### Domain separation (manuscript, "Labelled NIZK in the ROM")

The manuscript requires the NIZK's random oracle to be separated from every hash
evaluated *inside* the statement. Inside the statement we have only SHAKE256
(commitment, `μ`, `c̃`, SampleInBall), whose padding uses the domain suffix
`1111` (byte `0x1F`). Every NIZK oracle call uses **cSHAKE256** (SP 800-185) with
a non-empty customization string, whose padding uses the suffix `00`
(byte `0x04`):

| oracle | cSHAKE256 customization `S` |
|---|---|
| statement digest | `MOBS-v1/stmt` |
| Fiat–Shamir transcript | `MOBS-Ligero-v1/FS` |
| Merkle leaves | `MOBS-Ligero-v1/leaf` |
| Merkle inner nodes | `MOBS-Ligero-v1/node` |

So the two families never share a Keccak-f input block structure, and the four
NIZK oracles are mutually separated by `S`. `src/xof.c` implements cSHAKE256 over
the reference `fips202.c` and is tested against SP 800-185 samples #3/#4 and
PyCryptodome (`tests/test_xof.c`).

## 2. Constraint system

`src/cs.[ch]` is an R1CS-equivalent system over the Goldilocks field
`F_p`, `p = 2^64 − 2^32 + 1`:

* **Z-wires**: outputs of multiplication constraints `x_i · y_i = z_i`, where
  `x_i, y_i` are affine combinations of wires;
* **F-wires**: free witness values (constrained only linearly);
* **linear constraints** `Σ c_j w_j + k = 0`.

Gadgets (`src/gadgets.c`): boolean `u·u = u`; `XOR(a,b) = a + b − 2ab`;
bit decomposition with booleanity; `[a = k]` via an inverse hint
(`t = d·inv`, `e = 1 − t`, `d·e = 0`); materialization of an affine expression
into an F-wire (used to keep linear combinations short).

### 2.1 Keccak-f[1600] (`src/keccak_circuit.c`)

State bits are wires known to be boolean.

* θ: the 5-bit column sum is decomposed into 3 boolean wires (its low bit is the
  parity) — 3 mults per column; `D = C[x−1] ⊕ rot(C[x+1])` — 1 mult;
  `A ⊕ D` — 1 mult per state bit.
* ρ, π: wire permutation (free). ι: affine.
* χ: `a ⊕ ((1 − b)·c)` with 2 mults per bit; the output is materialized as an
  F-wire, which is boolean because it equals an exact {0,1}-valued expression.

That is 6,080 multiplications per round and ≈146 k per permutation. SHAKE256
padding (`0x1F … 0x80`) and absorption of constants are folded into affine
expressions. The circuit is tested against the reference `fips202.c` for input
lengths 0, 1, 31, 135, 136, 137, 200, 271, 272, 300 bytes (block boundaries
included) and outputs of up to 2176 bits (`tests/test_keccak.c`).

### 2.2 The opening relation (`src/mldsa_circuit.c`)

| (O) | manuscript | circuit |
|---|---|---|
| O1 | `m_D = y` | 256 linear constraints per opened attribute on the witness bits of `m_i` |
| O2 | `C = SHAKE256(DS_com‖r‖m)` | Keccak circuit; `r`, `m` are witness bits; `C` stays internal (never revealed) |
| O3 | `μ = SHAKE256(tr ‖ 0x00 ‖ 16 ‖ ctx_ML ‖ DS_iss ‖ C, 512)` | Keccak circuit; `tr = H(pk)` is a public constant |
| O4 | `c = SampleInBall_B(c̃)` | Keccak on `c̃`; rejection-sampling automaton (one-hot state over `τ+1` values, accept bit per candidate byte, range check `notdone·(ip − byte + …) ∈ [0,256)`), the `τ` selected indices `j_k` as F-wires, and `τ` conditional swaps on a one-hot position vector; signs from the first 8 bytes |
| O5 | `w' = A z − c t₁ 2^d` | per coefficient an exact *integer* identity `Σ a·z − 2^d Σ t₁·c = Q·k + r⁺` with `r⁺ ∈ [0,Q)` (23 bits + upper check) and `k` range-checked; `A` (expanded from `ρ`) and `t₁` are public constants in coefficient form, the negacyclic convolution is unrolled |
| O6 | `w'₁ = UseHint(h, w')` | `Decompose(r⁺) = (r₁, r₀)` with `r⁺ = 2γ₂u + r₀`, the `u = (q−1)/2γ₂` corner case via an equality gadget, the sign bit `[r₀ > 0]` via a range check, then the FIPS 204 `UseHint` case analysis with two equality gadgets and two products |
| O7 | `c̃ = SHAKE256(μ ‖ w1Encode(w'₁), 2λ)` | Keccak circuit over the bit encoding of `w'₁` (6 bits per coefficient for ML-DSA-44, 4 for 65/87); equality with the witness bits of `c̃` |
| O8 | `‖z‖∞ < γ₁ − β`, `wt(h) ≤ ω` | `z + (γ₁−β−1) ∈ [0, 2(γ₁−β−1)]` by bit decomposition plus upper check; `Σ h + slack = ω` with a boolean slack |

**No wrap-around.** O5 is checked over `F_p` but encodes an integer equation: the
largest `|Σ a·z| + 2^d·τ·max|t₁|` is `< 2^53` for ML-DSA-87, far below `p/2`,
and `k` is range-checked, so the field equation implies the integer equation.

**Correctness of the relation** (manuscript, Lemma "relation ⇔ verification")
is tested by `tests/test_mldsa_circuit.c` for the three parameter sets:
an honest FIPS 204 signature satisfies all constraints; the in-circuit
SampleInBall equals the reference `poly_challenge`; the verifier-side
(witness-free) circuit has exactly the prover's structure; and a wrong disclosed
value, a wrong public key, a forged hidden attribute and a corrupted `z` each
violate a constraint. End-to-end negative cases (wrong context, wrong `D`,
tampered proof, …) are in `tests/test_mobs.c`.

### 2.3 Sizes (`n = 8`, opening every other position)

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Keccak-f permutations | 12 | 13 | 16 |
| multiplications | 1,992,807 | 2,245,688 | 2,815,034 |
| free wires | 478,596 | 521,778 | 650,380 |
| linear constraints | 580,486 | 635,316 | 791,454 |
| committed rows (`RT`) | 416 | 476 | 609 |

Keccak accounts for 83–88 % of the multiplications. The permutation counts match
Table 2 of the manuscript; only (O2) grows with `n` (1 permutation per 136
bytes of `DS_com ‖ r ‖ m`).

## 3. The NIZK: Ligero + BCS (`src/ligero.c`)

### 3.1 Encoding

Rows have `K = 2^14` slots: `ℓ = K − t_pad` witness slots and `t_pad ≥ t`
random padding slots. Witness slots hold, in order, the F-wires and Z-wires
(`[F | Z]`), then the left inputs `X`, then the right inputs `Y` of all
multiplications. A row is the unique polynomial of degree `< K` with those
values on `H = ⟨ω_K⟩`; its codeword is its evaluation on the coset
`L = 7·⟨ω_n⟩`, `n = 4K` (Reed–Solomon, rate 1/4, `L ∩ H = ∅` since 7 generates
`F_p^*`). Masking rows:

* `u'_s` (degree `< K`, uniform) for the interleaved test;
* `q'_s` (degree `< 2K−1`, uniform subject to `Σ_H q'_s = 0`) for the linear test;
* `p'_s` (degree `< 2K−1`, uniform subject to vanishing on the `ℓ` witness points of `H`) for the quadratic test.

All `RT` rows are committed column-wise in one Merkle tree over `n = 2^16`
leaves; leaf `j` is `cSHAKE256(salt_j ‖ column_j)` with a fresh `HB`-byte salt.

### 3.2 Protocol (one commitment, three parallel tests, one query)

1. Prover commits (root).
2. Challenges from the transcript (statement digest, label, header, root):
   `r_I` (one coefficient per data row), `r_L` (one per linear constraint and per
   `X`/`Y` wiring equation), `r_Q` (one per `Z` row).
3. Prover sends `w_s = Σ r_I p_r + u'_s` (`K` coefficients),
   `q_s = Σ R_r·p_r + q'_s` and `p_s = Σ r_Q (p_X p_Y − p_Z) + p'_s`
   (`2K−1` coefficients each), where `R_r` interpolates the random combination
   of all linear constraints restricted to row `r`.
4. `t` column indices from the transcript (after the polynomials); the prover
   opens those columns with Merkle paths.
5. Verifier: Merkle paths; `Σ_H q_s = target`; `p_s = 0` on the `ℓ` witness
   points; and, at every opened column, consistency of `w_s, q_s, p_s` with the
   opened entries. The X/Y wiring (`x_i = ⟨X_i, w⟩ + k_i`) is part of the
   linear test, so the quadratic test is over committed values only.

### 3.3 Parameters and soundness

`lg_params_level(λ)` (`K = 2^14`, rate 1/4, `d = n − K + 1`, `e = ⌊(d−1)/4⌋`):

| | λ = 128 (ML-DSA-44) | λ = 192 (ML-DSA-65) | λ = 256 (ML-DSA-87) |
|---|---|---|---|
| opened columns `t` | 428 | 641 | 855 |
| column-query error `(1 − e/n)^t` | 2^−128.2 | 2^−192.0 | 2^−256.1 |
| `t_pad` (≥ t) | 512 | 768 | 1024 |
| interleaved reps `s_I`, error `((e+1)/p)^{s_I}` | 3, 2^−151 | 4, 2^−201 | 6, 2^−302 |
| linear / quadratic reps `s_L = s_Q`, error `p^{−s}` each | 2, 2^−128 | 3, 2^−192 | 4, 2^−256 |
| Merkle digest / salt `HB` | 32 B | 48 B | 64 B |

* `t` is set by the dominant column term. For the linear and quadratic tests a
  wrong polynomial agrees with the opened data on at most `e + 2K − 2` of the
  `n` columns, i.e. per-column pass probability `≤ 0.69 < 1 − e/n ≈ 0.81`.
* `e < d/4`, as required by the interleaved-test lemma of AHIV17.
* Round-by-round soundness of the BCS-compiled argument is about `2^−λ+1` per
  round, plus `O(Q²/2^{8·HB})` for Merkle collisions; an attacker making `Q`
  oracle queries succeeds with probability `≲ Q · 2^−λ+1` (grinding). The
  digest length `HB = 2λ` bits keeps collision resistance at `λ` bits for every
  level (an earlier version used 32 bytes for all levels, which capped
  ML-DSA-65/87 at 128 bits).
* All challenges are sampled from the cSHAKE256 transcript by rejection
  (field elements) or masking (column indices, `n` is a power of two).

### 3.4 Zero knowledge

* Each data row has `t_pad ≥ t` uniformly random slots, so its evaluations on
  any `t` points of `L` are uniform and independent of the witness (a row is
  `Z_W·q + interpolant`, with `deg q < t_pad` uniform).
* `w_s`, `q_s`, `p_s` are uniform in the affine space the verifier checks,
  because the masking rows are uniform in the corresponding linear spaces; the
  opened masking entries are then determined by the other opened data. This is
  the standard Ligero simulator.
* Unopened columns are hidden by the salted leaves (`2λ`-bit salts).
* Fiat–Shamir: the simulator programs the transcript oracle; HVZK + BCS gives
  (statistical, up to programming collisions) NIZK in the ROM.

Consequently an opening reveals nothing beyond `(n, D, y_D, pk)` — in particular
not `C`, `r`, `c̃`, `z`, `h` or the hidden attributes — which is what the
manuscript's blindness and multi-show unlinkability theorems need.

**SampleInBall bound.** The circuit allows `B` SHAKE256 blocks. The probability
that an honest `c̃` needs more is `2^−203` (ML-DSA-44, 128 candidate bytes),
`2^−140` (ML-DSA-65) and `2^−365` (ML-DSA-87 with `B = 2`; one block would give
`2^−88`). User₂ rejects such signatures. A malicious signer could only cause an
abort this way, which it can do anyway; it learns nothing about `m`.

### 3.5 Online extraction and non-malleability

The OMUF-MO theorem needs *online simulation-extractability* (OSE). For
BCS-type arguments this is obtained by straight-line extraction from the
adversary's oracle queries: from an accepting proof with root `ρ`, the
extractor follows the `MOBS-Ligero-v1/node` queries down to the
`MOBS-Ligero-v1/leaf` queries, recovers (all but a few) columns, decodes each
row within distance `e`, and reads off the witness. Simulated proofs for other
`(x, ℓ)` do not help, because `x` and `ℓ` are absorbed before the root and the
proof is uniquely determined by `(root, polynomials)` up to Merkle collisions.
This is the standard argument (BCS16; see Chiesa–Fenzi, TCC 2024, for a formal
treatment of straight-line extraction for Micali/BCS-style SNARKs in the ROM).
A full written proof of OSE for this exact instantiation, with masking rows
and three tests, is not part of this deliverable.

**QROM.** Soundness of the BCS transform is known in the QROM
(Chiesa–Manohar–Spooner, TCC 2019); online extraction in the QROM, which the
manuscript would need for a fully post-quantum OMUF-MO proof, is open
(manuscript, Sect. 9).

## 4. Proof format (`MOBSLG02`)

```
magic "MOBSLG02" (8) | u32 ×11: λ, logK, logρ, t_pad, t, s_I, s_L, s_Q, RT, nF, nZ (44)
| root (HB)
| w_1..w_{s_I} (K field elements each) | q_1..q_{s_L}, p_1..p_{s_Q} (2K−1 each)
| t × [ salt (HB) | column (RT field elements) | Merkle path (16 × HB) ]
```

Field elements are 8-byte little-endian and must be `< p` (non-canonical
encodings are rejected). The verifier recomputes the header from *its own*
parameters and the circuit shape and rejects any mismatch, then checks the exact
length.

`|τ| = 52 + HB + 8·(s_I·K + (s_L+s_Q)(2K−1)) + t·(HB + 8·RT + 16·HB)`;
for ML-DSA-44, `n = 8`: 1.44 MB of polynomials + 1.66 MB of columns = 2.96 MiB.

## 5. Implementation properties and limitations

* **Unmodified ML-DSA.** `third_party/dilithium` is pq-crystals/dilithium at
  commit `d35ba3fe` (3 June 2026, FIPS 204 with context strings), compiled
  as is. Its KAT hashes for modes 2/3/5 match the published `SHA256SUMS`.
* **Not constant time.** Circuit construction and witness generation branch on
  witness values (Decompose, SampleInBall, range checks) and the prover's
  memory access pattern depends on the attributes. Openings must be computed on
  a device trusted against local side channels. The verifier handles public
  data only.
* **Randomness:** `randombytes()` from the reference code (`getrandom` on Linux).
* **Resources:** peak memory ≈ 0.76 GiB (ML-DSA-44), 0.79 GiB (65), 1.04 GiB (87);
  single-threaded. Row encoding (NTTs), leaf hashing and the three tests are
  embarrassingly parallel.
* **Proof size.** 2.9–7.6 MiB is 3–8× larger than optimized hash-based systems
  for a similar relation (GordieHowe: 549 KiB for the ML-DSA-44 signature
  sub-relation; blind ML-DSA signatures of BB26: ≈ 1 MB). The circuit layer is
  proof-system-agnostic (R1CS-equivalent), so it can be exported to such systems.
  Cheap improvements: Merkle multi-proofs, a sumcheck layer for the Keccak
  part (Longfellow-style), an extension field to reduce repetitions.
* **Not included:** predicates `Φ(m)` (e.g., ranges on attributes; the gadgets
  exist), revocation, key-binding to a device key, threshold issuance.
* **Research prototype**, not audited. Do not use in production.
