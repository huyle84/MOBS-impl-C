/* test_field.c -- unit tests for the Goldilocks field and NTT. */
#include <stdio.h>
#include <stdlib.h>
#include "../src/field.h"

static uint64_t rng_state = 0x123456789abcdefULL;
static uint64_t rnd64(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}
static fe rndfe(void) {
  uint64_t x;
  do x = rnd64(); while (x >= FE_P);
  return x;
}

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

int main(void) {
  /* mul vs. naive 128-bit mod */
  for (int i = 0; i < 200000; i++) {
    fe a = rndfe(), b = rndfe();
    __uint128_t ref = ((__uint128_t)a * b) % FE_P;
    CHECK(fe_mul(a, b) == (fe)ref, "mul");
    __uint128_t s = ((__uint128_t)a + b) % FE_P;
    CHECK(fe_add(a, b) == (fe)s, "add");
    __uint128_t d = ((__uint128_t)a + FE_P - b) % FE_P;
    CHECK(fe_sub(a, b) == (fe)d, "sub");
  }
  /* edge cases */
  CHECK(fe_mul(FE_P - 1, FE_P - 1) == 1, "(-1)^2");
  CHECK(fe_add(FE_P - 1, FE_P - 1) == FE_P - 2, "add edge");
  CHECK(fe_add(FE_P - 1, 1) == 0, "add wrap");
  for (int i = 0; i < 1000; i++) {
    fe a = rndfe();
    if (!a) continue;
    CHECK(fe_mul(a, fe_inv(a)) == 1, "inv");
  }
  /* roots of unity */
  for (unsigned lg = 1; lg <= 20; lg++) {
    fe w = fe_root_of_unity(lg);
    CHECK(fe_pow(w, (uint64_t)1 << lg) == 1, "root order");
    CHECK(fe_pow(w, (uint64_t)1 << (lg - 1)) == FE_P - 1, "root primitive");
  }
  /* NTT vs naive DFT, and roundtrip */
  for (unsigned lg = 1; lg <= 8; lg++) {
    size_t n = (size_t)1 << lg;
    fe *a = malloc(n * sizeof(fe)), *b = malloc(n * sizeof(fe));
    for (size_t i = 0; i < n; i++) a[i] = b[i] = rndfe();
    fe_ntt(b, lg);
    fe w = fe_root_of_unity(lg);
    for (size_t j = 0; j < n; j++) {
      fe x = fe_pow(w, j);
      CHECK(b[j] == fe_poly_eval(a, n, x), "ntt vs dft");
    }
    fe_intt(b, lg);
    for (size_t i = 0; i < n; i++) CHECK(b[i] == a[i], "intt roundtrip");
    free(a);
    free(b);
  }
  /* coset eval / interp */
  {
    unsigned lg = 10;
    size_t n = (size_t)1 << lg;
    fe *a = calloc(n, sizeof(fe)), *e = malloc(n * sizeof(fe)), *c = malloc(n * sizeof(fe));
    for (size_t i = 0; i < n / 2; i++) a[i] = rndfe();
    fe_coset_eval(e, a, n / 2, FE_GEN, lg);
    fe w = fe_root_of_unity(lg);
    for (size_t j = 0; j < n; j += 97) {
      fe x = fe_mul(FE_GEN, fe_pow(w, j));
      CHECK(e[j] == fe_poly_eval(a, n / 2, x), "coset eval");
    }
    fe_coset_interp(c, e, FE_GEN, lg);
    for (size_t i = 0; i < n; i++) CHECK(c[i] == a[i], "coset interp");
    free(a); free(e); free(c);
  }
  /* large NTT roundtrip */
  {
    unsigned lg = 16;
    size_t n = (size_t)1 << lg;
    fe *a = malloc(n * sizeof(fe)), *b = malloc(n * sizeof(fe));
    for (size_t i = 0; i < n; i++) a[i] = b[i] = rndfe();
    fe_ntt(b, lg);
    fe_intt(b, lg);
    for (size_t i = 0; i < n; i++) CHECK(b[i] == a[i], "large roundtrip");
    free(a); free(b);
  }
  if (fails) { printf("test_field: %d failures\n", fails); return 1; }
  printf("test_field: OK\n");
  return 0;
}
