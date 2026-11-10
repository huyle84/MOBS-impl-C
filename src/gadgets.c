/*
 * gadgets.c -- basic gadgets.
 */
#include "gadgets.h"
#include <stdlib.h>

void g_bits(cs_t *cs, const lc_t *a, uint64_t aval, unsigned nb, wire_t *bits_out) {
  if (nb > 63) abort();
  if (cs->has_wit) {
    if (nb < 64 && (aval >> nb) != 0) cs->bad = 1;
    if (lc_eval(cs, a) != fe_reduce64(aval)) cs->bad = 1;
  }
  /* constraint: a - sum 2^i b_i = 0 (built with the big-constraint API) */
  wire_t bw[64];
  for (unsigned i = 0; i < nb; i++) bw[i] = cs_bit(cs, cs->has_wit ? (int)((aval >> i) & 1) : 0);
  cs_lin_begin(cs);
  for (uint32_t t = 0; t < a->n; t++) cs_lin_term(cs, a->w[t], a->c[t]);
  for (unsigned i = 0; i < nb; i++) cs_lin_term(cs, bw[i], fe_neg((fe)1 << i));
  cs_lin_end(cs, a->k);
  if (bits_out)
    for (unsigned i = 0; i < nb; i++) bits_out[i] = bw[i];
}

void g_mul(cs_t *cs, lc_t *out, const lc_t *a, const lc_t *b) {
  /* constant shortcuts keep the circuit small and are value-independent */
  if (lc_is_const(a)) {
    lc_t t;
    lc_zero(&t);
    lc_addc(&t, b, a->k);
    lc_copy(out, &t);
    return;
  }
  if (lc_is_const(b)) {
    lc_t t;
    lc_zero(&t);
    lc_addc(&t, a, b->k);
    lc_copy(out, &t);
    return;
  }
  wire_t m = cs_mul(cs, a, b);
  lc_wire(out, m);
}

void g_xor(cs_t *cs, lc_t *out, const lc_t *a, const lc_t *b) {
  lc_t m, r;
  g_mul(cs, &m, a, b);
  lc_zero(&r);
  lc_add(&r, a);
  lc_add(&r, b);
  lc_addc(&r, &m, fe_neg(2));
  lc_copy(out, &r);
}

void g_eq_const(cs_t *cs, lc_t *e_out, const lc_t *a, fe k) {
  lc_t d;
  lc_copy(&d, a);
  lc_addk(&d, fe_neg(k));
  fe dv = lc_eval(cs, &d);
  wire_t inv = cs_free_wire(cs, (cs->has_wit && dv != 0) ? fe_inv(dv) : 0);
  lc_t linv;
  lc_wire(&linv, inv);
  wire_t t = cs_mul(cs, &d, &linv); /* t = d * inv */
  lc_t e;
  lc_const(&e, 1);
  lc_term(&e, t, fe_neg(1)); /* e = 1 - t */
  wire_t s = cs_mul(cs, &d, &e); /* s = d * e must be 0 */
  lc_t ls;
  lc_wire(&ls, s);
  cs_lin(cs, &ls);
  lc_copy(e_out, &e);
}

wire_t g_mat(cs_t *cs, const lc_t *a) {
  wire_t w = cs_free_wire(cs, lc_eval(cs, a));
  cs_lin_begin(cs);
  for (uint32_t t = 0; t < a->n; t++) cs_lin_term(cs, a->w[t], a->c[t]);
  cs_lin_term(cs, w, fe_neg(1));
  cs_lin_end(cs, a->k);
  return w;
}

void g_witness_bytes(cs_t *cs, lc_t *bits_out, const uint8_t *bytes, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++)
    for (int j = 0; j < 8; j++) {
      int b = (cs->has_wit && bytes) ? (bytes[i] >> j) & 1 : 0;
      lc_wire(&bits_out[8 * i + j], cs_bit(cs, b));
    }
}

void g_const_bytes(lc_t *bits_out, const uint8_t *bytes, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++)
    for (int j = 0; j < 8; j++) lc_const(&bits_out[8 * i + j], (fe)((bytes[i] >> j) & 1));
}
