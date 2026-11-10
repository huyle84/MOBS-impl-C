/*
 * field.h -- arithmetic in the Goldilocks prime field F_p, p = 2^64 - 2^32 + 1.
 *
 * Used as the base field of the Ligero argument. ML-DSA arithmetic modulo
 * q = 8380417 is embedded into F_p as bounded integer arithmetic (see
 * mldsa_circuit.c), which is sound because every value involved is range-
 * checked and smaller than p/2 in absolute value.
 */
#ifndef MOBS_FIELD_H
#define MOBS_FIELD_H

#include <stdint.h>
#include <stddef.h>

typedef uint64_t fe;

#define FE_P 0xFFFFFFFF00000001ULL
#define FE_EPS 0xFFFFFFFFULL /* 2^64 mod p = 2^32 - 1 */
#define FE_GEN 7ULL           /* generator of F_p^* */

static inline fe fe_reduce64(uint64_t a) { return a >= FE_P ? a - FE_P : a; }

static inline fe fe_add(fe a, fe b) {
  /* a, b < p: if a + b overflows 2^64, the true sum is r + 2^64 = r + EPS (mod p),
   * and r + EPS = a + b - p < p, so no further reduction is needed. */
  uint64_t r = a + b;
  if (r < a) return r + FE_EPS;
  return fe_reduce64(r);
}

static inline fe fe_neg(fe a) { return a == 0 ? 0 : FE_P - a; }

static inline fe fe_sub(fe a, fe b) { return a >= b ? a - b : a + (FE_P - b); }

static inline fe fe_reduce128(__uint128_t x) {
  uint64_t lo = (uint64_t)x;
  uint64_t hi = (uint64_t)(x >> 64);
  uint64_t hi_hi = hi >> 32;
  uint64_t hi_lo = hi & FE_EPS;
  uint64_t t0 = lo - hi_hi;
  if (lo < hi_hi) t0 -= FE_EPS; /* borrow: add p == subtract EPS mod 2^64 */
  uint64_t t1 = hi_lo * FE_EPS;
  uint64_t res = t0 + t1;
  if (res < t1) res += FE_EPS; /* carry */
  return fe_reduce64(res);
}

static inline fe fe_mul(fe a, fe b) { return fe_reduce128((__uint128_t)a * b); }

/* field element from a signed 64-bit integer (|a| < p) */
static inline fe fe_from_i64(int64_t a) {
  return a >= 0 ? fe_reduce64((uint64_t)a) : fe_neg(fe_reduce64((uint64_t)(-a)));
}

fe fe_pow(fe a, uint64_t e);
fe fe_inv(fe a);                 /* a != 0 */
fe fe_root_of_unity(unsigned logn); /* primitive 2^logn-th root of unity */

/* In-place radix-2 NTT of length 2^logn, natural order in and out:
 * out[j] = sum_i in[i] * w^(i*j), w = primitive 2^logn-th root. */
void fe_ntt(fe *a, unsigned logn);
/* inverse NTT (includes the 1/n factor) */
void fe_intt(fe *a, unsigned logn);

/* Evaluate the polynomial with coefficients a[0..alen-1] (alen <= 2^logn)
 * on the coset shift*<w_n>: out[j] = a(shift * w_n^j). out has 2^logn entries. */
void fe_coset_eval(fe *out, const fe *a, size_t alen, fe shift, unsigned logn);
/* Inverse of fe_coset_eval: from evaluations on shift*<w_n> to 2^logn coefficients. */
void fe_coset_interp(fe *coeffs, const fe *evals, fe shift, unsigned logn);

/* Horner evaluation */
fe fe_poly_eval(const fe *a, size_t alen, fe x);

#endif
