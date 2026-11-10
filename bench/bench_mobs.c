/*
 * bench_mobs.c -- timings and sizes of MOBS[ML-DSA] with production parameters.
 * Usage: ./build/bench_mobs2 [n1 n2 ...]   (default n = 4 8 16 32)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mobs.h"
#include "randombytes.h"

static double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
  size_t ns[16] = {4, 8, 16, 32};
  int cnt = 4;
  if (argc > 1) {
    cnt = 0;
    for (int i = 1; i < argc && cnt < 16; i++) ns[cnt++] = (size_t)atoi(argv[i]);
  }
  const lg_params_t *P = mobs_get_ligero_params();
  printf("# MOBS[ML-DSA] benchmark: ML-DSA mode %d, Ligero K=2^%u, rate 1/%u, t=%u (column bound 2^%.1f), sI=%u sL=%u sQ=%u\n",
         DILITHIUM_MODE, P->logK, 1u << P->logrho, P->t, lg_column_soundness_bits(P), P->sI, P->sL, P->sQ);
  uint8_t pk[MOBS_PK_BYTES], sk[MOBS_SK_BYTES];
  const int IT = 200;
  double t = now();
  for (int i = 0; i < IT; i++) mobs_keygen(pk, sk);
  double tk = (now() - t) / IT;
  uint8_t *m = malloc(MOBS_MAX_ATTRS * MOBS_ATTR_BYTES);
  randombytes(m, MOBS_MAX_ATTRS * MOBS_ATTR_BYTES);
  mobs_user_state_t st;
  mobs_cred_t cred;
  uint8_t rho1[MOBS_RHO1_BYTES], rho2[MOBS_RHO2_BYTES];
  t = now();
  for (int i = 0; i < IT; i++) mobs_user1(&st, rho1, m, 8);
  double tu1 = (now() - t) / IT;
  t = now();
  for (int i = 0; i < IT; i++) mobs_sign(rho2, rho1, sk);
  double ts = (now() - t) / IT;
  t = now();
  for (int i = 0; i < IT; i++) mobs_user2(&cred, &st, rho2, pk);
  double tu2 = (now() - t) / IT;
  printf("| step | time |\n|---|---|\n| KeyGen | %.3f ms |\n| User1 (commit, n=8) | %.3f ms |\n| Sign (FIPS 204) | %.3f ms |\n| User2 (verify) | %.3f ms |\n\n",
         tk * 1e3, tu1 * 1e3, ts * 1e3, tu2 * 1e3);
  printf("| n | Keccak-f perms | mults | free wires | linear constr. | rows | opening size | open (build+prove) | verify (build+check) |\n");
  printf("|---|---|---|---|---|---|---|---|---|\n");
  for (int c = 0; c < cnt; c++) {
    size_t n = ns[c];
    mobs_user1(&st, rho1, m, n);
    mobs_sign(rho2, rho1, sk);
    if (mobs_user2(&cred, &st, rho2, pk)) { printf("user2 failed\n"); return 1; }
    uint8_t dmask[MOBS_MAX_ATTRS] = {0};
    for (size_t i = 0; i < n; i += 2) dmask[i] = 1; /* open every other position */
    uint8_t *tau;
    size_t len;
    mobs_open_stats_t so, sv;
    const uint8_t ctx[] = "bench";
    if (mobs_open(&tau, &len, &cred, pk, dmask, ctx, sizeof(ctx), &so)) { printf("open failed\n"); return 1; }
    int ok = mobs_verify(pk, n, dmask, m, ctx, sizeof(ctx), tau, len, &sv) == 0;
    printf("| %zu | %zu | %zu | %zu | %zu | %zu | %.2f MiB | %.2f + %.2f s | %.2f + %.2f s%s |\n", n, so.perms, so.mults,
           so.free_wires, so.lin, so.rows, len / 1048576.0, so.t_build, so.t_prove, sv.t_build, sv.t_verify,
           ok ? "" : " (REJECTED!)");
    fflush(stdout);
    free(tau);
  }
  free(m);
  return 0;
}
