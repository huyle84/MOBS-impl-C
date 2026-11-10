/* test_ligero.c -- completeness and soundness checks for the Ligero argument. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/ligero.h"
#include "../src/gadgets.h"
#include "../src/keccak_circuit.h"

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("ok:   %s\n", msg); } while (0)

static uint64_t rs;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

/* A random circuit: free wires, bits, products and linear relations.
 * Structure depends only on the seed; values only on the seed as well. */
static void build_random(cs_t *cs, uint64_t seed, size_t nmul) {
  rs = seed;
  wire_t pool[4096];
  size_t np = 0;
  for (int i = 0; i < 64; i++) pool[np++] = cs_free_wire(cs, rnd() % FE_P);
  for (int i = 0; i < 64; i++) pool[np++] = cs_bit(cs, (int)(rnd() & 1));
  for (size_t i = 0; i < nmul; i++) {
    lc_t a, b;
    lc_zero(&a);
    lc_zero(&b);
    for (int t = 0; t < 3; t++) lc_term(&a, pool[rnd() % np], rnd() % FE_P);
    for (int t = 0; t < 2; t++) lc_term(&b, pool[rnd() % np], rnd() % 1000);
    lc_addk(&a, rnd() % 7);
    wire_t z = cs_mul(cs, &a, &b);
    if (np < 4096) pool[np++] = z;
    if (i % 5 == 0) { /* linear relation: f = c1*z + c2*pool[k] + 3 */
      lc_t l;
      lc_zero(&l);
      lc_term(&l, z, rnd() % FE_P);
      lc_term(&l, pool[rnd() % np], 5);
      lc_addk(&l, 3);
      wire_t f = g_mat(cs, &l);
      if (np < 4096) pool[np++] = f;
    }
  }
}

int main(void) {
  lg_params_t P;
  lg_params_test(&P);
  printf("test params: K=2^%u rate=1/%u tpad=%u t=%u (column bound 2^%.1f)\n", P.logK, 1u << P.logrho, P.tpad, P.t,
         lg_column_soundness_bits(&P));
  const uint8_t stmt[] = "statement", label[] = "ctx-1", label2[] = "ctx-2";

  for (int round = 0; round < 3; round++) {
    size_t nmul = round == 0 ? 50 : (round == 1 ? 700 : 3000);
    cs_t cs, vcs;
    cs_init(&cs, 1);
    cs_init(&vcs, 0);
    build_random(&cs, 1000 + round, nmul);
    build_random(&vcs, 1000 + round, nmul);
    printf("-- random circuit: mults=%zu free=%zu lin=%zu\n", cs.nZ, cs.nF, cs.LIN.n);
    CHECK(cs_check(&cs, 1) == 0, "random circuit satisfied");
    uint8_t *pf;
    size_t pl;
    int rc = lg_prove(&cs, &P, stmt, sizeof(stmt), label, sizeof(label), &pf, &pl, 0, NULL);
    CHECK(rc == 0, "prover succeeds");
    CHECK(lg_verify(&vcs, &P, stmt, sizeof(stmt), label, sizeof(label), pf, pl, NULL) == 0, "honest proof accepted");
    CHECK(lg_verify(&vcs, &P, stmt, sizeof(stmt), label2, sizeof(label2), pf, pl, NULL) != 0, "wrong label rejected");
    CHECK(lg_verify(&vcs, &P, (const uint8_t *)"other", 5, label, sizeof(label), pf, pl, NULL) != 0,
          "wrong statement rejected");
    /* bit flips at various positions of the proof */
    size_t positions[] = {60, 100, 8 * 70 + 200, pl / 2, pl - 40, pl - 1};
    int all = 1;
    for (size_t k = 0; k < sizeof(positions) / sizeof(positions[0]); k++) {
      pf[positions[k]] ^= 0x10;
      if (lg_verify(&vcs, &P, stmt, sizeof(stmt), label, sizeof(label), pf, pl, NULL) == 0) all = 0;
      pf[positions[k]] ^= 0x10;
    }
    CHECK(all, "every tampered proof rejected");
    free(pf);

    /* cheating prover 1: violate a multiplication constraint */
    cs.valZ[cs.nZ / 2] = fe_add(cs.valZ[cs.nZ / 2], 1);
    CHECK(lg_prove(&cs, &P, stmt, sizeof(stmt), label, sizeof(label), &pf, &pl, 0, NULL) == -2,
          "prover refuses unsatisfied witness");
    rc = lg_prove(&cs, &P, stmt, sizeof(stmt), label, sizeof(label), &pf, &pl, 1, NULL);
    CHECK(rc == 0 && lg_verify(&vcs, &P, stmt, sizeof(stmt), label, sizeof(label), pf, pl, NULL) != 0,
          "proof for violated multiplication rejected");
    free(pf);
    cs.valZ[cs.nZ / 2] = fe_sub(cs.valZ[cs.nZ / 2], 1);
    /* cheating prover 2: violate a linear constraint via a free wire */
    cs.valF[cs.nF - 1] = fe_add(cs.valF[cs.nF - 1], 7);
    rc = lg_prove(&cs, &P, stmt, sizeof(stmt), label, sizeof(label), &pf, &pl, 1, NULL);
    CHECK(rc == 0 && lg_verify(&vcs, &P, stmt, sizeof(stmt), label, sizeof(label), pf, pl, NULL) != 0,
          "proof for violated linear constraint rejected");
    free(pf);
    cs_free(&cs);
    cs_free(&vcs);
  }

  /* production parameters on one Keccak-f permutation */
  {
    lg_params_t PP;
    lg_params_default(&PP);
    printf("default params: K=2^%u rate=1/%u tpad=%u t=%u sI=%u sL=%u sQ=%u (column bound 2^%.1f)\n", PP.logK,
           1u << PP.logrho, PP.tpad, PP.t, PP.sI, PP.sL, PP.sQ, lg_column_soundness_bits(&PP));
    cs_t cs, vcs;
    cs_init(&cs, 1);
    cs_init(&vcs, 0);
    uint8_t msg[100];
    for (int i = 0; i < 100; i++) msg[i] = (uint8_t)i;
    lc_t in[800], in2[800], out[256], out2[256];
    g_witness_bytes(&cs, in, msg, 100);
    g_witness_bytes(&vcs, in2, NULL, 100);
    shake256_circuit(&cs, out, 256, in, 800);
    shake256_circuit(&vcs, out2, 256, in2, 800);
    uint8_t *pf;
    size_t pl;
    lg_stats_t sp, sv;
    int rc = lg_prove(&cs, &PP, stmt, sizeof(stmt), label, sizeof(label), &pf, &pl, 0, &sp);
    printf("keccak proof: mults=%zu rows=%zu size=%zu bytes prove=%.2fs\n", cs.nZ, sp.rows, pl, sp.t_total);
    CHECK(rc == 0, "prover (default params) succeeds");
    CHECK(lg_verify(&vcs, &PP, stmt, sizeof(stmt), label, sizeof(label), pf, pl, &sv) == 0,
          "honest proof accepted (default params)");
    printf("verify=%.2fs\n", sv.t_total);
    pf[pl / 3] ^= 1;
    CHECK(lg_verify(&vcs, &PP, stmt, sizeof(stmt), label, sizeof(label), pf, pl, NULL) != 0,
          "tampered proof rejected (default params)");
    free(pf);
    cs_free(&cs);
    cs_free(&vcs);
  }
  if (fails) { printf("test_ligero: %d failures\n", fails); return 1; }
  printf("test_ligero: OK\n");
  return 0;
}
