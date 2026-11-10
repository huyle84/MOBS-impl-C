/* test_mobs.c -- end-to-end test of MOBS[ML-DSA] with production Ligero parameters. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/mobs.h"
#include "randombytes.h"

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("ok:   %s\n", msg); } while (0)

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fast")) {
    lg_params_t P;
    lg_params_test(&P);
    mobs_set_ligero_params(&P);
    printf("(fast mode: insecure test parameters)\n");
  }
  const lg_params_t *P = mobs_get_ligero_params();
  printf("ML-DSA mode %d, Ligero K=2^%u lambda=%u t=%u tpad=%u sI=%u sL=%u sQ=%u, column soundness 2^%.1f\n", DILITHIUM_MODE, P->logK, P->lambda, P->t, P->tpad, P->sI, P->sL, P->sQ,
         lg_column_soundness_bits(P));
  const size_t n = 8;
  uint8_t pk[MOBS_PK_BYTES], sk[MOBS_SK_BYTES], pk2[MOBS_PK_BYTES], sk2[MOBS_SK_BYTES];
  mobs_keygen(pk, sk);
  mobs_keygen(pk2, sk2);
  uint8_t m[8 * MOBS_ATTR_BYTES];
  randombytes(m, sizeof(m));

  /* blind signing */
  mobs_user_state_t st;
  mobs_cred_t cred;
  uint8_t rho1[MOBS_RHO1_BYTES], rho2[MOBS_RHO2_BYTES];
  CHECK(mobs_user1(&st, rho1, m, n) == 0, "user1: commitment computed");
  CHECK(mobs_sign(rho2, rho1, sk) == 0, "signer: one FIPS 204 ML-DSA signing operation");
  {
    uint8_t bad[MOBS_RHO2_BYTES];
    memcpy(bad, rho2, sizeof(bad));
    bad[100] ^= 4;
    mobs_cred_t tmp;
    CHECK(mobs_user2(&tmp, &st, bad, pk) != 0, "user2 rejects a corrupted signature");
    CHECK(mobs_user2(&tmp, &st, rho2, pk2) != 0, "user2 rejects a signature under another key");
  }
  CHECK(mobs_user2(&cred, &st, rho2, pk) == 0, "user2: base signature accepted");

  /* opening of positions {0, 3} */
  uint8_t dsel[8] = {1, 0, 0, 1, 0, 0, 0, 0};
  const uint8_t ctx[] = "verifier-nonce-0001";
  uint8_t *tau;
  size_t taulen;
  mobs_open_stats_t so, sv;
  int rc = mobs_open(&tau, &taulen, &cred, pk, dsel, ctx, sizeof(ctx), &so);
  CHECK(rc == 0, "open(D={0,3})");
  printf("   circuit: %zu Keccak-f perms, %zu mults, %zu free wires, %zu linear; %zu committed rows\n", so.perms,
         so.mults, so.free_wires, so.lin, so.rows);
  printf("   opening size: %zu bytes (%.2f MiB); build %.2fs, prove %.2fs\n", taulen, taulen / 1048576.0, so.t_build,
         so.t_prove);
  rc = mobs_verify(pk, n, dsel, m, ctx, sizeof(ctx), tau, taulen, &sv);
  CHECK(rc == 0, "verify accepts the honest opening");
  printf("   verify: build %.2fs, check %.2fs\n", sv.t_build, sv.t_verify);

  uint8_t y2[sizeof(m)];
  memcpy(y2, m, sizeof(m));
  y2[3 * MOBS_ATTR_BYTES] ^= 1;
  CHECK(mobs_verify(pk, n, dsel, y2, ctx, sizeof(ctx), tau, taulen, NULL) != 0, "wrong opened value rejected");
  memcpy(y2, m, sizeof(m));
  y2[1 * MOBS_ATTR_BYTES] ^= 1; /* hidden position changed: must not matter */
  CHECK(mobs_verify(pk, n, dsel, y2, ctx, sizeof(ctx), tau, taulen, NULL) == 0, "values at hidden positions are ignored");
  const uint8_t ctx2[] = "verifier-nonce-0002";
  CHECK(mobs_verify(pk, n, dsel, m, ctx2, sizeof(ctx2), tau, taulen, NULL) != 0, "replay under another context rejected");
  CHECK(mobs_verify(pk2, n, dsel, m, ctx, sizeof(ctx), tau, taulen, NULL) != 0, "wrong public key rejected");
  uint8_t dsel2[8] = {1, 0, 0, 0, 0, 0, 0, 0};
  CHECK(mobs_verify(pk, n, dsel2, m, ctx, sizeof(ctx), tau, taulen, NULL) != 0, "different position set rejected");
  tau[taulen / 2] ^= 0x01;
  CHECK(mobs_verify(pk, n, dsel, m, ctx, sizeof(ctx), tau, taulen, NULL) != 0, "tampered opening rejected");
  free(tau);

  /* full opening (= ordinary blind signature) and empty opening */
  uint8_t Dall[8] = {1, 1, 1, 1, 1, 1, 1, 1}, Dnone[8] = {0};
  rc = mobs_open(&tau, &taulen, &cred, pk, Dall, ctx, sizeof(ctx), NULL);
  CHECK(rc == 0 && mobs_verify(pk, n, Dall, m, ctx, sizeof(ctx), tau, taulen, NULL) == 0,
        "full opening D=[n] verifies (induced blind signature)");
  free(tau);
  rc = mobs_open(&tau, &taulen, &cred, pk, Dnone, ctx, sizeof(ctx), NULL);
  CHECK(rc == 0 && mobs_verify(pk, n, Dnone, m, ctx, sizeof(ctx), tau, taulen, NULL) == 0,
        "empty opening D={} verifies (possession only)");
  free(tau);

  /* a credential for a different vector cannot open a value it does not contain */
  {
    uint8_t m3[sizeof(m)];
    randombytes(m3, sizeof(m3));
    mobs_user_state_t st3;
    mobs_cred_t c3;
    mobs_user1(&st3, rho1, m3, n);
    mobs_sign(rho2, rho1, sk);
    mobs_user2(&c3, &st3, rho2, pk);
    memcpy(c3.m, m, sizeof(m)); /* try to open attributes of the first credential */
    rc = mobs_open(&tau, &taulen, &c3, pk, dsel, ctx, sizeof(ctx), NULL);
    CHECK(rc != 0, "prover cannot open attributes not certified by its base signature");
    if (rc == 0) free(tau);
  }
  if (fails) { printf("test_mobs: %d failures\n", fails); return 1; }
  printf("test_mobs: OK\n");
  return 0;
}
