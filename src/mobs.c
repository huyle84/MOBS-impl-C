/*
 * mobs.c -- MOBS[ML-DSA] API.
 */
#include "mobs.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fips202.h"
#include "mldsa_circuit.h"
#include "randombytes.h"
#include "sign.h"
#include "xof.h"

static lg_params_t g_params;
static int g_params_set = 0;

void mobs_set_ligero_params(const lg_params_t *P) {
  g_params = *P;
  g_params_set = 1;
}
const lg_params_t *mobs_get_ligero_params(void) {
  if (!g_params_set) {
    /* match the NIST category of the ML-DSA parameter set */
#if DILITHIUM_MODE == 2
    lg_params_level(&g_params, 128);
#elif DILITHIUM_MODE == 3
    lg_params_level(&g_params, 192);
#else
    lg_params_level(&g_params, 256);
#endif
    g_params_set = 1;
  }
  return &g_params;
}

static double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int mobs_keygen(uint8_t pk[MOBS_PK_BYTES], uint8_t sk[MOBS_SK_BYTES]) { return crypto_sign_keypair(pk, sk); }

static void commit(uint8_t C[MOBS_CBYTES], const uint8_t *r, const uint8_t *m, size_t n) {
  keccak_state s;
  shake256_init(&s);
  shake256_absorb(&s, MOBS_DS_COM, MOBS_DS_BYTES);
  shake256_absorb(&s, r, MOBS_RBYTES);
  shake256_absorb(&s, m, n * MOBS_ATTR_BYTES);
  shake256_finalize(&s);
  shake256_squeeze(C, MOBS_CBYTES, &s);
}

int mobs_user1(mobs_user_state_t *st, uint8_t rho1[MOBS_RHO1_BYTES], const uint8_t *m, size_t n) {
  if (n == 0 || n > MOBS_MAX_ATTRS) return -1;
  st->n = n;
  memcpy(st->m, m, n * MOBS_ATTR_BYTES);
  randombytes(st->r, MOBS_RBYTES);
  commit(st->C, st->r, st->m, n);
  memcpy(rho1, st->C, MOBS_CBYTES);
  return 0;
}

/* The signer: one unmodified FIPS 204 signing operation on DS_iss || rho1. */
int mobs_sign(uint8_t rho2[MOBS_RHO2_BYTES], const uint8_t rho1[MOBS_RHO1_BYTES], const uint8_t sk[MOBS_SK_BYTES]) {
  uint8_t M[MOBS_DS_BYTES + MOBS_CBYTES];
  size_t siglen;
  memcpy(M, MOBS_DS_ISS, MOBS_DS_BYTES);
  memcpy(M + MOBS_DS_BYTES, rho1, MOBS_CBYTES);
  return crypto_sign_signature(rho2, &siglen, M, sizeof(M), MOBS_CTX_ML, MOBS_DS_BYTES, sk);
}

int mobs_sig_provable(const uint8_t sig[MOBS_RHO2_BYTES]) {
  /* replay SampleInBall on the first MOBS_SIB_BLOCKS blocks */
  uint8_t buf[SHAKE256_RATE * MOBS_SIB_BLOCKS];
  keccak_state s;
  shake256_init(&s);
  shake256_absorb(&s, sig, CTILDEBYTES);
  shake256_finalize(&s);
  shake256_squeeze(buf, sizeof(buf), &s);
  size_t pos = 8;
  for (int i = 256 - TAU; i < 256; i++) {
    for (;;) {
      if (pos >= sizeof(buf)) return 0;
      if (buf[pos++] <= i) break;
    }
  }
  return 1;
}

int mobs_user2(mobs_cred_t *cred, const mobs_user_state_t *st, const uint8_t rho2[MOBS_RHO2_BYTES],
               const uint8_t pk[MOBS_PK_BYTES]) {
  uint8_t M[MOBS_DS_BYTES + MOBS_CBYTES];
  memcpy(M, MOBS_DS_ISS, MOBS_DS_BYTES);
  memcpy(M + MOBS_DS_BYTES, st->C, MOBS_CBYTES);
  if (crypto_sign_verify(rho2, MOBS_RHO2_BYTES, M, sizeof(M), MOBS_CTX_ML, MOBS_DS_BYTES, pk)) return -1;
  if (!mobs_sig_provable(rho2)) return -2; /* negligible; caller may request a fresh signature */
  cred->n = st->n;
  memcpy(cred->m, st->m, st->n * MOBS_ATTR_BYTES);
  memcpy(cred->r, st->r, MOBS_RBYTES);
  memcpy(cred->sig, rho2, MOBS_RHO2_BYTES);
  return 0;
}

/* statement digest bound by Fiat-Shamir: parameter set, pk, n, D, y_D */
static void stmt_digest(uint8_t out[64], const uint8_t *pk, size_t n, const uint8_t *dmask, const uint8_t *y) {
  keccak_state s;
  uint8_t hdr[8] = {'M', 'O', 'B', 'S', (uint8_t)DILITHIUM_MODE, (uint8_t)n, (uint8_t)(n >> 8), 0};
  mobs_cshake256_init(&s, "MOBS-v1/stmt"); /* NIZK oracle: cSHAKE256, see xof.h */
  shake256_absorb(&s, hdr, 8);
  shake256_absorb(&s, pk, MOBS_PK_BYTES);
  for (size_t i = 0; i < n; i++) {
    uint8_t b = dmask[i] ? 1 : 0;
    shake256_absorb(&s, &b, 1);
    if (b) shake256_absorb(&s, y + i * MOBS_ATTR_BYTES, MOBS_ATTR_BYTES);
  }
  mobs_cshake256_finalize(&s);
  shake256_squeeze(out, 64, &s);
}

int mobs_open(uint8_t **tau, size_t *taulen, const mobs_cred_t *cred, const uint8_t pk[MOBS_PK_BYTES],
              const uint8_t *dmask, const uint8_t *ctx, size_t ctxlen, mobs_open_stats_t *stats) {
  double t0 = now();
  uint8_t dm[MOBS_MAX_ATTRS];
  for (size_t i = 0; i < cred->n; i++) dm[i] = dmask[i] ? 1 : 0;
  mobs_stmt_t st = {cred->n, pk, dm, cred->m};
  mobs_wit_t wit = {cred->m, cred->r, cred->sig};
  cs_t cs;
  cs_init(&cs, 1);
  mobs_circuit_stats_t cst;
  if (mobs_build_circuit(&cs, &st, &wit, &cst) || cs.bad) {
    cs_free(&cs);
    return -1;
  }
  double t1 = now();
  uint8_t dg[64];
  stmt_digest(dg, pk, cred->n, dm, cred->m);
  lg_stats_t ls;
  int rc = lg_prove(&cs, mobs_get_ligero_params(), dg, sizeof(dg), ctx, ctxlen, tau, taulen, 0, &ls);
  if (stats) {
    stats->mults = cst.mults;
    stats->free_wires = cst.free_wires;
    stats->lin = cst.lin;
    stats->perms = cst.perms;
    stats->rows = ls.rows;
    stats->t_build = t1 - t0;
    stats->t_prove = now() - t1;
  }
  cs_free(&cs);
  return rc;
}

int mobs_verify(const uint8_t pk[MOBS_PK_BYTES], size_t n, const uint8_t *dmask, const uint8_t *y, const uint8_t *ctx,
                size_t ctxlen, const uint8_t *tau, size_t taulen, mobs_open_stats_t *stats) {
  double t0 = now();
  if (n == 0 || n > MOBS_MAX_ATTRS) return -1;
  uint8_t dm[MOBS_MAX_ATTRS];
  for (size_t i = 0; i < n; i++) dm[i] = dmask[i] ? 1 : 0;
  mobs_stmt_t st = {n, pk, dm, y};
  cs_t cs;
  cs_init(&cs, 0);
  if (mobs_build_circuit(&cs, &st, NULL, NULL)) {
    cs_free(&cs);
    return -1;
  }
  double t1 = now();
  uint8_t dg[64];
  stmt_digest(dg, pk, n, dm, y);
  int rc = lg_verify(&cs, mobs_get_ligero_params(), dg, sizeof(dg), ctx, ctxlen, tau, taulen, NULL);
  if (stats) {
    stats->t_build = t1 - t0;
    stats->t_verify = now() - t1;
  }
  cs_free(&cs);
  return rc;
}
