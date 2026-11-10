/*
 * field.c -- Goldilocks field: exponentiation, inversion, NTT, coset evaluation.
 */
#include "field.h"
#include <stdlib.h>
#include <string.h>

fe fe_pow(fe a, uint64_t e) {
  fe r = 1;
  while (e) {
    if (e & 1) r = fe_mul(r, a);
    a = fe_mul(a, a);
    e >>= 1;
  }
  return r;
}

fe fe_inv(fe a) { return fe_pow(a, FE_P - 2); }

fe fe_root_of_unity(unsigned logn) {
  /* p - 1 = 2^32 * (2^32 - 1) */
  fe g = fe_pow(FE_GEN, (FE_P - 1) >> 32); /* primitive 2^32-th root */
  for (unsigned i = logn; i < 32; i++) g = fe_mul(g, g);
  return g;
}

static void bitrev(fe *a, size_t n) {
  for (size_t i = 1, j = 0; i < n; i++) {
    size_t bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      fe t = a[i];
      a[i] = a[j];
      a[j] = t;
    }
  }
}

/* twiddle cache: tw[logn] holds w^0..w^(n/2-1) for the 2^logn-th root w */
#define MAX_LOGN 24
static fe *tw_cache[MAX_LOGN + 1];
static fe *itw_cache[MAX_LOGN + 1];

static const fe *twiddles(unsigned logn, int inverse) {
  fe **cache = inverse ? itw_cache : tw_cache;
  if (!cache[logn]) {
    size_t half = (size_t)1 << (logn ? logn - 1 : 0);
    fe *t = (fe *)malloc(sizeof(fe) * (half ? half : 1));
    fe w = fe_root_of_unity(logn);
    if (inverse) w = fe_inv(w);
    fe x = 1;
    for (size_t i = 0; i < half; i++) {
      t[i] = x;
      x = fe_mul(x, w);
    }
    cache[logn] = t;
  }
  return cache[logn];
}

static void ntt_core(fe *a, unsigned logn, int inverse) {
  size_t n = (size_t)1 << logn;
  if (n == 1) return;
  bitrev(a, n);
  const fe *tw = twiddles(logn, inverse);
  for (unsigned s = 1; s <= logn; s++) {
    size_t m = (size_t)1 << s, half = m >> 1;
    size_t stride = n / m; /* twiddle stride in the full table */
    for (size_t k = 0; k < n; k += m) {
      for (size_t j = 0; j < half; j++) {
        fe t = fe_mul(tw[j * stride], a[k + j + half]);
        fe u = a[k + j];
        a[k + j] = fe_add(u, t);
        a[k + j + half] = fe_sub(u, t);
      }
    }
  }
}

void fe_ntt(fe *a, unsigned logn) { ntt_core(a, logn, 0); }

void fe_intt(fe *a, unsigned logn) {
  ntt_core(a, logn, 1);
  size_t n = (size_t)1 << logn;
  fe ninv = fe_inv((fe)n);
  for (size_t i = 0; i < n; i++) a[i] = fe_mul(a[i], ninv);
}

void fe_coset_eval(fe *out, const fe *a, size_t alen, fe shift, unsigned logn) {
  size_t n = (size_t)1 << logn;
  fe s = 1;
  for (size_t i = 0; i < n; i++) {
    if (i < alen) {
      out[i] = fe_mul(a[i], s);
      s = fe_mul(s, shift);
    } else {
      out[i] = 0;
    }
  }
  fe_ntt(out, logn);
}

void fe_coset_interp(fe *coeffs, const fe *evals, fe shift, unsigned logn) {
  size_t n = (size_t)1 << logn;
  if (coeffs != evals) memcpy(coeffs, evals, n * sizeof(fe));
  fe_intt(coeffs, logn);
  fe sinv = fe_inv(shift), s = 1;
  for (size_t i = 0; i < n; i++) {
    coeffs[i] = fe_mul(coeffs[i], s);
    s = fe_mul(s, sinv);
  }
}

fe fe_poly_eval(const fe *a, size_t alen, fe x) {
  fe r = 0;
  for (size_t i = alen; i-- > 0;) r = fe_add(fe_mul(r, x), a[i]);
  return r;
}
