/*
 * mldsa_circuit.h -- the MOBS opening relation R_open for ML-DSA (Fig. 5 of the
 * v2 manuscript, constraints O1-O8):
 *
 *   public : pk, n, disclosure mask D, disclosed values y
 *   witness: m in M^n, r, sigma = (c~, z, h) with
 *     (O1) m_D = y
 *     (O2) C  = SHAKE256(DS_com || r || m_1 || ... || m_n, l_c)
 *     (O3) mu = SHAKE256(tr || 0x00 || |ctx| || ctx || DS_iss || C, 512)
 *     (O4) c  = SampleInBall_B(c~)
 *     (O5) w' = A z - c t1 2^d   (mod q, as bounded integer arithmetic in F_p)
 *     (O6) w1 = UseHint(h, w')
 *     (O7) c~ = SHAKE256(mu || w1Encode(w1), 2*lambda)
 *     (O8) ||z||_inf < gamma1 - beta,  wt(h) <= omega
 */
#ifndef MOBS_MLDSA_CIRCUIT_H
#define MOBS_MLDSA_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>
#include "cs.h"
#include "mobs_params.h"

typedef struct {
  size_t n;              /* number of attributes */
  const uint8_t *pk;     /* CRYPTO_PUBLICKEYBYTES */
  const uint8_t *dmask;  /* n bytes, 1 = disclosed */
  const uint8_t *y;      /* n * MOBS_ATTR_BYTES (only disclosed positions are read) */
} mobs_stmt_t;

typedef struct {
  const uint8_t *m;      /* n * MOBS_ATTR_BYTES */
  const uint8_t *r;      /* MOBS_RBYTES */
  const uint8_t *sig;    /* CRYPTO_BYTES (ML-DSA signature on DS_iss || C) */
} mobs_wit_t;

typedef struct {
  size_t perms, mults, free_wires, lin;
} mobs_circuit_stats_t;

/* Builds R_open into cs (cs must be initialized with has_wit = (wit != NULL)).
 * Returns 0 on success, -1 if the public key cannot be decoded. */
int mobs_build_circuit(cs_t *cs, const mobs_stmt_t *st, const mobs_wit_t *wit, mobs_circuit_stats_t *stats);

/* For tests: the challenge polynomial c computed inside the circuit (witness mode). */
extern int32_t mobs_debug_c[256];

#endif
