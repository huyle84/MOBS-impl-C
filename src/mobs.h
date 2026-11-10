/*
 * mobs.h -- Modular-Opening Blind Signatures from unmodified ML-DSA (FIPS 204).
 *
 *   Signing (two moves, fully blind):
 *     user   : (st, rho1) <- mobs_user1(m)        rho1 = C = SHAKE256(DS_com || r || m)
 *     signer : rho2 <- mobs_sign(sk, rho1)        rho2 = ML-DSA.Sign(sk, DS_iss || C, ctx_ML)
 *     user   : cred <- mobs_user2(st, rho2, pk)   checks ML-DSA.Verify
 *   Opening module (any positions, any number of times, unlinkable):
 *     tau <- mobs_open(cred, pk, D, ctx)          Ligero NIZK for R_open
 *     0/1 <- mobs_verify(pk, n, D, y, ctx, tau)
 */
#ifndef MOBS_H
#define MOBS_H

#include <stddef.h>
#include <stdint.h>
#include "api.h"
#include "ligero.h"
#include "mobs_params.h"

#define MOBS_PK_BYTES CRYPTO_PUBLICKEYBYTES
#define MOBS_SK_BYTES CRYPTO_SECRETKEYBYTES
#define MOBS_RHO1_BYTES MOBS_CBYTES
#define MOBS_RHO2_BYTES CRYPTO_BYTES

typedef struct {
  size_t n;
  uint8_t m[MOBS_MAX_ATTRS * MOBS_ATTR_BYTES];
  uint8_t r[MOBS_RBYTES];
  uint8_t C[MOBS_CBYTES];
} mobs_user_state_t;

typedef struct {
  size_t n;
  uint8_t m[MOBS_MAX_ATTRS * MOBS_ATTR_BYTES];
  uint8_t r[MOBS_RBYTES];
  uint8_t sig[MOBS_RHO2_BYTES]; /* base signature: ML-DSA signature on DS_iss || C */
} mobs_cred_t;

typedef struct {
  size_t mults, free_wires, lin, perms, rows;
  double t_build, t_prove, t_verify;
} mobs_open_stats_t;

/* Ligero parameters used by open/verify (default: lg_params_default). */
void mobs_set_ligero_params(const lg_params_t *P);
const lg_params_t *mobs_get_ligero_params(void);

int mobs_keygen(uint8_t pk[MOBS_PK_BYTES], uint8_t sk[MOBS_SK_BYTES]);
int mobs_user1(mobs_user_state_t *st, uint8_t rho1[MOBS_RHO1_BYTES], const uint8_t *m, size_t n);
int mobs_sign(uint8_t rho2[MOBS_RHO2_BYTES], const uint8_t rho1[MOBS_RHO1_BYTES], const uint8_t sk[MOBS_SK_BYTES]);
int mobs_user2(mobs_cred_t *cred, const mobs_user_state_t *st, const uint8_t rho2[MOBS_RHO2_BYTES],
               const uint8_t pk[MOBS_PK_BYTES]);
/* dmask: n bytes (1 = open position i). On success *tau is malloc'ed. */
int mobs_open(uint8_t **tau, size_t *taulen, const mobs_cred_t *cred, const uint8_t pk[MOBS_PK_BYTES],
              const uint8_t *dmask, const uint8_t *ctx, size_t ctxlen, mobs_open_stats_t *stats);
/* y: n * MOBS_ATTR_BYTES; only positions with dmask[i] = 1 are read. Returns 0 if valid. */
int mobs_verify(const uint8_t pk[MOBS_PK_BYTES], size_t n, const uint8_t *dmask, const uint8_t *y, const uint8_t *ctx,
                size_t ctxlen, const uint8_t *tau, size_t taulen, mobs_open_stats_t *stats);

/* 1 if SampleInBall(c~) of this signature fits into MOBS_SIB_BLOCKS blocks. */
int mobs_sig_provable(const uint8_t sig[MOBS_RHO2_BYTES]);

#endif
