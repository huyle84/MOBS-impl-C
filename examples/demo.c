/*
 * demo.c -- a complete MOBS[ML-DSA] run:
 *   issuer key generation, fully blind signing of an attribute vector,
 *   and two unlinkable openings of different positions for different verifiers.
 *
 * Usage: ./build/demo2 [--fast]   (--fast uses insecure test parameters)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mobs.h"

static void set_attr(uint8_t *m, size_t i, const char *s) {
  memset(m + i * MOBS_ATTR_BYTES, 0, MOBS_ATTR_BYTES);
  memcpy(m + i * MOBS_ATTR_BYTES, s, strlen(s) < MOBS_ATTR_BYTES ? strlen(s) : MOBS_ATTR_BYTES);
}

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fast")) {
    lg_params_t P;
    lg_params_test(&P);
    mobs_set_ligero_params(&P);
  }
  const size_t n = 6;
  uint8_t m[6 * MOBS_ATTR_BYTES];
  set_attr(m, 0, "serial:7f3a9c21e08b44d1");
  set_attr(m, 1, "name:Nguyen Van A");
  set_attr(m, 2, "birth-year:1998");
  set_attr(m, 3, "country:VN");
  set_attr(m, 4, "expiry:2027-12-31");
  set_attr(m, 5, "role:student");

  /* issuer */
  uint8_t pk[MOBS_PK_BYTES], sk[MOBS_SK_BYTES];
  mobs_keygen(pk, sk);

  /* blind signing: the signer only sees a 32/48/64-byte string */
  mobs_user_state_t st;
  mobs_cred_t cred;
  uint8_t rho1[MOBS_RHO1_BYTES], rho2[MOBS_RHO2_BYTES];
  mobs_user1(&st, rho1, m, n);
  printf("user -> signer : rho1 (%d bytes) = ", MOBS_RHO1_BYTES);
  for (int i = 0; i < 8; i++) printf("%02x", rho1[i]);
  printf("...\n");
  mobs_sign(rho2, rho1, sk);
  printf("signer -> user : rho2 = ML-DSA signature (%d bytes)\n", MOBS_RHO2_BYTES);
  if (mobs_user2(&cred, &st, rho2, pk)) { printf("signature rejected\n"); return 1; }

  /* opening 1: verifier A learns only the country */
  uint8_t dA[6] = {0, 0, 0, 1, 0, 0};
  const char ctxA[] = "verifier-A|nonce=81273";
  uint8_t *tau;
  size_t len;
  mobs_open_stats_t so;
  mobs_open(&tau, &len, &cred, pk, dA, (const uint8_t *)ctxA, strlen(ctxA), &so);
  printf("open {country}            : %zu bytes, %.1fs -> verify %s\n", len, so.t_build + so.t_prove,
         mobs_verify(pk, n, dA, m, (const uint8_t *)ctxA, strlen(ctxA), tau, len, NULL) == 0 ? "ACCEPT" : "REJECT");
  free(tau);

  /* opening 2: verifier B learns the serial and the expiry (e.g. e-cash style) */
  uint8_t dB[6] = {1, 0, 0, 0, 1, 0};
  const char ctxB[] = "verifier-B|nonce=55102";
  mobs_open(&tau, &len, &cred, pk, dB, (const uint8_t *)ctxB, strlen(ctxB), &so);
  printf("open {serial, expiry}     : %zu bytes, %.1fs -> verify %s\n", len, so.t_build + so.t_prove,
         mobs_verify(pk, n, dB, m, (const uint8_t *)ctxB, strlen(ctxB), tau, len, NULL) == 0 ? "ACCEPT" : "REJECT");
  /* a cheating claim: pretend the expiry is later */
  uint8_t y[6 * MOBS_ATTR_BYTES];
  memcpy(y, m, sizeof(y));
  set_attr(y, 4, "expiry:2099-12-31");
  printf("same opening, forged value: verify %s\n",
         mobs_verify(pk, n, dB, y, (const uint8_t *)ctxB, strlen(ctxB), tau, len, NULL) == 0 ? "ACCEPT" : "REJECT");
  free(tau);
  return 0;
}
