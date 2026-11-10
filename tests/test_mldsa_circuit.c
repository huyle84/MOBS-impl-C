/* test_mldsa_circuit.c -- the ML-DSA opening relation: honest witness satisfies
 * all constraints, tampered statements/witnesses do not, and the verifier-side
 * circuit is structurally identical to the prover-side circuit. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/mldsa_circuit.h"
#include "../src/keccak_circuit.h"
#include "api.h"
#include "fips202.h"
#include "poly.h"
#include "packing.h"
#include "randombytes.h"
#include "sign.h"

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("ok:   %s\n", msg); } while (0)

static double now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec * 1e-9; }

static int same_mat(const lcmat_t *a, const lcmat_t *b) {
  if (a->n != b->n || a->nt != b->nt) return 0;
  if (memcmp(a->off, b->off, (a->n + 1) * sizeof(size_t))) return 0;
  if (memcmp(a->tw, b->tw, a->nt * sizeof(wire_t))) return 0;
  if (memcmp(a->tc, b->tc, a->nt * sizeof(fe))) return 0;
  if (memcmp(a->k, b->k, a->n * sizeof(fe))) return 0;
  return 1;
}

int main(void) {
  const size_t n = 8;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], pk2[CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
  crypto_sign_keypair(pk, sk);
  crypto_sign_keypair(pk2, sk2);
  uint8_t m[8 * MOBS_ATTR_BYTES], r[MOBS_RBYTES];
  randombytes(m, sizeof(m));
  randombytes(r, sizeof(r));
  /* C = SHAKE256(DS_com || r || m) ; M = DS_iss || C */
  uint8_t cin[MOBS_DS_BYTES + MOBS_RBYTES + sizeof(m)], M[MOBS_DS_BYTES + MOBS_CBYTES];
  memcpy(cin, MOBS_DS_COM, MOBS_DS_BYTES);
  memcpy(cin + MOBS_DS_BYTES, r, MOBS_RBYTES);
  memcpy(cin + MOBS_DS_BYTES + MOBS_RBYTES, m, sizeof(m));
  memcpy(M, MOBS_DS_ISS, MOBS_DS_BYTES);
  shake256(M + MOBS_DS_BYTES, MOBS_CBYTES, cin, sizeof(cin));
  uint8_t sig[CRYPTO_BYTES];
  size_t siglen;
  crypto_sign_signature(sig, &siglen, M, sizeof(M), MOBS_CTX_ML, MOBS_DS_BYTES, sk);
  CHECK(crypto_sign_verify(sig, siglen, M, sizeof(M), MOBS_CTX_ML, MOBS_DS_BYTES, pk) == 0, "reference ML-DSA verifies issuer signature");

  uint8_t dmask[8] = {1, 0, 0, 1, 0, 0, 0, 0};
  mobs_stmt_t st = {n, pk, dmask, m};
  mobs_wit_t wit = {m, r, sig};

  /* prover-side circuit */
  cs_t cs;
  cs_init(&cs, 1);
  mobs_circuit_stats_t stt;
  double t0 = now();
  mobs_build_circuit(&cs, &st, &wit, &stt);
  double t1 = now();
  printf("circuit: perms=%zu mults=%zu free=%zu lin=%zu X.nt=%zu Y.nt=%zu LIN.nt=%zu (%.2fs)\n", stt.perms, stt.mults,
         stt.free_wires, stt.lin, cs.X.nt, cs.Y.nt, cs.LIN.nt, t1 - t0);
  CHECK(cs.bad == 0, "witness generation consistent (no range/hint mismatch)");
  size_t viol = cs_check(&cs, 1);
  CHECK(viol == 0, "honest witness satisfies all constraints");
  /* c computed in-circuit equals reference SampleInBall */
  {
    uint8_t ctil[CTILDEBYTES];
    polyvecl z;
    polyveck h;
    unpack_sig(ctil, &z, &h, sig);
    poly c;
    poly_challenge(&c, ctil);
    int eq = 1;
    for (int i = 0; i < 256; i++) if (c.coeffs[i] != mobs_debug_c[i]) eq = 0;
    CHECK(eq, "in-circuit SampleInBall equals reference poly_challenge");
  }

  /* verifier-side circuit is structurally identical */
  cs_t vcs;
  cs_init(&vcs, 0);
  mobs_build_circuit(&vcs, &st, NULL, NULL);
  CHECK(vcs.nZ == cs.nZ && vcs.nF == cs.nF && same_mat(&vcs.X, &cs.X) && same_mat(&vcs.Y, &cs.Y) &&
            same_mat(&vcs.LIN, &cs.LIN),
        "verifier circuit identical to prover circuit");
  cs_free(&vcs);
  cs_free(&cs);

  /* negative 1: disclosed value differs from witness */
  {
    uint8_t y2[sizeof(m)];
    memcpy(y2, m, sizeof(m));
    y2[3 * MOBS_ATTR_BYTES + 5] ^= 1;
    mobs_stmt_t st2 = {n, pk, dmask, y2};
    cs_init(&cs, 1);
    mobs_build_circuit(&cs, &st2, &wit, NULL);
    CHECK(cs_check(&cs, 0) > 0, "wrong disclosed value is rejected");
    cs_free(&cs);
  }
  /* negative 2: wrong public key */
  {
    mobs_stmt_t st2 = {n, pk2, dmask, m};
    cs_init(&cs, 1);
    mobs_build_circuit(&cs, &st2, &wit, NULL);
    CHECK(cs_check(&cs, 0) > 0 || cs.bad, "wrong public key is rejected");
    cs_free(&cs);
  }
  /* negative 3: signature on a different commitment (attribute changed) */
  {
    uint8_t m2[sizeof(m)];
    memcpy(m2, m, sizeof(m));
    m2[40] ^= 0x80; /* attribute 1, not disclosed */
    mobs_wit_t w2 = {m2, r, sig};
    cs_init(&cs, 1);
    mobs_build_circuit(&cs, &st, &w2, NULL);
    CHECK(cs_check(&cs, 0) > 0 || cs.bad, "forged hidden attribute is rejected");
    cs_free(&cs);
  }
  /* negative 4: corrupted signature */
  {
    uint8_t sig2[CRYPTO_BYTES];
    memcpy(sig2, sig, sizeof(sig));
    sig2[CTILDEBYTES + 10] ^= 1; /* inside z */
    mobs_wit_t w2 = {m, r, sig2};
    cs_init(&cs, 1);
    mobs_build_circuit(&cs, &st, &w2, NULL);
    CHECK(cs_check(&cs, 0) > 0 || cs.bad, "corrupted signature is rejected");
    cs_free(&cs);
  }
  if (fails) { printf("test_mldsa_circuit: %d failures\n", fails); return 1; }
  printf("test_mldsa_circuit: OK\n");
  return 0;
}
