/*
 * ligero.h -- Ligero zero-knowledge argument (Ames, Hazay, Ishai,
 * Venkitasubramaniam, CCS 2017) over the Goldilocks field, made
 * non-interactive with the BCS/Fiat-Shamir transform using SHAKE256
 * (salted Merkle commitments + transcript hashing).
 *
 * Proves knowledge of a witness for a constraint system cs_t:
 *   - linear constraints (gadget constraints and x/y wiring),
 *   - multiplication constraints x_i * y_i = z_i.
 *
 * Committed matrix (rows of length ell = K - tpad witness slots):
 *   [ F-wires | Z-wires ] [ X ] [ Y ] [ masking rows ]
 * Each row is a random polynomial of degree < K agreeing with the row on the
 * first ell points of H = <w_K> and random on the remaining tpad points; its
 * codeword is its evaluation on the coset L = g*<w_n>, n = K * 2^logrho.
 *
 * Proof format ("MOBSLG02"): magic(8) | 11 x u32 (lambda, logK, logrho, tpad, t,
 * sI, sL, sQ, RT, nF, nZ) | Merkle root (HB) | test polynomials (8-byte field
 * elements) | t x [salt (HB) | column (RT field elements) | Merkle path (logn x HB)],
 * with HB = 32 / 48 / 64 bytes for lambda <= 128 / 192 / 256.
 */
#ifndef MOBS_LIGERO_H
#define MOBS_LIGERO_H

#include <stddef.h>
#include <stdint.h>
#include "cs.h"

typedef struct {
  unsigned logK;   /* message domain size K = 2^logK */
  unsigned logrho; /* code length n = K << logrho (rate 2^-logrho) */
  unsigned tpad;   /* random padding slots per row (>= t for zero knowledge) */
  unsigned t;      /* number of opened columns */
  unsigned sI, sL, sQ; /* repetitions of the interleaved / linear / quadratic tests */
  unsigned lambda; /* target soundness (bits) used to derive t */
} lg_params_t;

/* Production parameters for a soundness target of lambda bits (K=2^14, rate 1/4):
 * t from (1 - e/n)^t <= 2^-lambda, tpad >= t, repetitions from the per-test errors. */
void lg_params_level(lg_params_t *P, unsigned lambda);
/* lg_params_level(P, 128) */
void lg_params_default(lg_params_t *P);
/* Small parameters for fast functional tests only (NOT secure). */
void lg_params_test(lg_params_t *P);
/* log2 of the per-proof column-query soundness error bound (1 - e/n)^t */
double lg_column_soundness_bits(const lg_params_t *P);

typedef struct {
  double t_commit, t_tests, t_open, t_total;
  size_t rows, bytes;
} lg_stats_t;

/* Prover. cs must contain a witness. stmt/label are bound by Fiat-Shamir.
 * If allow_unsat == 0, refuses to prove an unsatisfied system (returns -2).
 * On success *proof is malloc'ed. */
int lg_prove(const cs_t *cs, const lg_params_t *P, const uint8_t *stmt, size_t stmtlen, const uint8_t *label,
             size_t labellen, uint8_t **proof, size_t *prooflen, int allow_unsat, lg_stats_t *stats);

/* Verifier. cs is the structure-only constraint system (has_wit = 0).
 * Returns 0 if the proof is accepted, a negative value otherwise. */
int lg_verify(const cs_t *cs, const lg_params_t *P, const uint8_t *stmt, size_t stmtlen, const uint8_t *label,
              size_t labellen, const uint8_t *proof, size_t prooflen, lg_stats_t *stats);

#endif
