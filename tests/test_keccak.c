/* test_keccak.c -- SHAKE256 circuit vs. the reference implementation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/keccak_circuit.h"
#include "../src/gadgets.h"
#include "fips202.h"

static uint64_t s = 88172645463325252ULL;
static uint8_t rb(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint8_t)s; }

int main(void) {
  size_t lens[] = {0, 1, 31, 135, 136, 137, 200, 271, 272, 300};
  size_t outs[] = {256, 512, 1088, 1600, 2176};
  int fails = 0;
  for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
    size_t len = lens[li];
    size_t ob = outs[li % 5];
    uint8_t *msg = malloc(len + 1);
    for (size_t i = 0; i < len; i++) msg[i] = rb();
    /* mix witness bits and public constant bits */
    cs_t cs;
    cs_init(&cs, 1);
    lc_t *in = malloc(sizeof(lc_t) * (8 * len + 1));
    size_t half = len / 2;
    g_const_bytes(in, msg, half);
    g_witness_bytes(&cs, in + 8 * half, msg + half, len - half);
    lc_t *out = malloc(sizeof(lc_t) * ob);
    keccak_circuit_perms = 0;
    shake256_circuit(&cs, out, ob, in, 8 * len);
    uint8_t *ref = malloc(ob / 8);
    shake256(ref, ob / 8, msg, len);
    int ok = 1;
    for (size_t i = 0; i < ob; i++)
      if (lc_eval(&cs, &out[i]) != (fe)((ref[i / 8] >> (i % 8)) & 1)) ok = 0;
    size_t viol = cs_check(&cs, 1);
    printf("len=%3zu outbits=%4zu perms=%zu mults=%zu free=%zu lin=%zu : %s, violations=%zu\n", len, ob,
           keccak_circuit_perms, cs.nZ, cs.nF, cs.LIN.n, ok ? "match" : "MISMATCH", viol);
    if (!ok || viol || cs.bad) fails++;
    /* tamper one witness bit -> constraints must fail */
    if (len - half > 0) {
      wire_t w = in[8 * half].w[0];
      cs.valZ[w] ^= 1;
      if (cs_check(&cs, 0) == 0) { printf("  tamper not detected!\n"); fails++; }
    }
    cs_free(&cs);
    free(msg); free(in); free(out); free(ref);
  }
  if (fails) { printf("test_keccak: %d failures\n", fails); return 1; }
  printf("test_keccak: OK\n");
  return 0;
}
