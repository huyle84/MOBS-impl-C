/*
 * test_xof.c -- cSHAKE256 against NIST SP 800-185 samples #3/#4 and further
 * vectors generated with an independent implementation (PyCryptodome).
 */
#include <stdio.h>
#include <string.h>
#include "xof.h"

static int hex2(const char *h, unsigned char *o, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
    o[i] = (unsigned char)v;
  }
  return 0;
}

int main(void) {
  static const struct { size_t inlen; const char *S; size_t L; const char *hex; } V[] = {
    {4, "Email Signature", 64, "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"},
    {200, "Email Signature", 64, "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb"},
    {0, "MOBS-Ligero-v1/FS", 32, "4b3660180e7d337a0c782349380c5bf1729287586d899aee07b10050ea261383"},
    {136, "MOBS-v1/stmt", 48, "229dd15bd885b777d6ca83e76bad043dba2dbf24046606f47ba69c810f3d4cd95407e68a42b513038859b46b66309ced"},
    {1000, "MOBS-Ligero-v1/leaf", 200, "35789ac099f83053df67993e888343c43cd4be3bfd3ec6d2db1e030e8ed1ac30350bf6a90734358eae451973bf000983db5ff86c4bc842e2f91ba4871e751f54f9134ca50f691fab8c7d6736a92d793f048eec9639604e85a638e7606f1644e39b65a3f3929cc243e3fff7f260d057b16a589f82143c429f47c378d7eb5bd5d790558d70af13c435c80cabc948e63a173964b58eb4094e4abe04775c1d9e230d8ac2e11605d19ac71d5d1a35ec6542344b7b8776a3f1d3f589f784261d1b2f8a810ab176948a0fc8"},
  };
  unsigned char in[1000], out[256], exp[256];
  int fails = 0;
  for (size_t v = 0; v < sizeof(V) / sizeof(V[0]); v++) {
    for (size_t i = 0; i < V[v].inlen; i++) in[i] = (unsigned char)(i % 256);
    mobs_cshake256(out, V[v].L, V[v].S, in, V[v].inlen);
    hex2(V[v].hex, exp, V[v].L);
    int ok = memcmp(out, exp, V[v].L) == 0;
    /* incremental absorption must give the same result */
    keccak_state s;
    mobs_cshake256_init(&s, V[v].S);
    for (size_t i = 0; i < V[v].inlen; i++) shake256_absorb(&s, in + i, 1);
    mobs_cshake256_finalize(&s);
    shake256_squeeze(out, V[v].L, &s);
    ok &= memcmp(out, exp, V[v].L) == 0;
    printf("%s  cSHAKE256(|X|=%zu, S=\"%s\", L=%zu)\n", ok ? "ok:  " : "FAIL:", V[v].inlen, V[v].S, 8 * V[v].L);
    fails += !ok;
  }
  printf("test_xof: %s\n", fails ? "FAILED" : "OK");
  return fails != 0;
}
