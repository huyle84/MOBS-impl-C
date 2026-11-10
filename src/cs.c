/*
 * cs.c -- constraint system storage and evaluation.
 */
#include "cs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *xrealloc(void *p, size_t sz) {
  void *q = realloc(p, sz ? sz : 1);
  if (!q) {
    fprintf(stderr, "out of memory (%zu bytes)\n", sz);
    abort();
  }
  return q;
}

static void lcmat_init(lcmat_t *m) {
  memset(m, 0, sizeof(*m));
  m->cap = 1024;
  m->off = xrealloc(NULL, (m->cap + 1) * sizeof(size_t));
  m->k = xrealloc(NULL, m->cap * sizeof(fe));
  m->capt = 4096;
  m->tw = xrealloc(NULL, m->capt * sizeof(wire_t));
  m->tc = xrealloc(NULL, m->capt * sizeof(fe));
  m->off[0] = 0;
}

static void lcmat_free(lcmat_t *m) {
  free(m->off);
  free(m->k);
  free(m->tw);
  free(m->tc);
  memset(m, 0, sizeof(*m));
}

static void lcmat_reserve_terms(lcmat_t *m, size_t extra) {
  if (m->nt + extra > m->capt) {
    while (m->nt + extra > m->capt) m->capt *= 2;
    m->tw = xrealloc(m->tw, m->capt * sizeof(wire_t));
    m->tc = xrealloc(m->tc, m->capt * sizeof(fe));
  }
}

static void lcmat_push_term(lcmat_t *m, wire_t w, fe c) {
  lcmat_reserve_terms(m, 1);
  m->tw[m->nt] = w;
  m->tc[m->nt] = c;
  m->nt++;
}

static void lcmat_end_row(lcmat_t *m, fe k) {
  if (m->n + 1 > m->cap) {
    m->cap *= 2;
    m->off = xrealloc(m->off, (m->cap + 1) * sizeof(size_t));
    m->k = xrealloc(m->k, m->cap * sizeof(fe));
  }
  m->k[m->n] = k;
  m->n++;
  m->off[m->n] = m->nt;
}

static void lcmat_push_lc(lcmat_t *m, const lc_t *a) {
  lcmat_reserve_terms(m, a->n);
  for (uint32_t i = 0; i < a->n; i++) {
    m->tw[m->nt] = a->w[i];
    m->tc[m->nt] = a->c[i];
    m->nt++;
  }
  lcmat_end_row(m, a->k);
}

void cs_init(cs_t *cs, int has_wit) {
  memset(cs, 0, sizeof(*cs));
  cs->has_wit = has_wit;
  cs->capF = 1024;
  cs->capZ = 1024;
  cs->valF = xrealloc(NULL, cs->capF * sizeof(fe));
  cs->valZ = xrealloc(NULL, cs->capZ * sizeof(fe));
  lcmat_init(&cs->X);
  lcmat_init(&cs->Y);
  lcmat_init(&cs->LIN);
}

void cs_free(cs_t *cs) {
  free(cs->valF);
  free(cs->valZ);
  lcmat_free(&cs->X);
  lcmat_free(&cs->Y);
  lcmat_free(&cs->LIN);
  memset(cs, 0, sizeof(*cs));
}

fe cs_val(const cs_t *cs, wire_t w) {
  if (!cs->has_wit) return 0;
  return WIRE_IS_F(w) ? cs->valF[WIRE_IDX(w)] : cs->valZ[w];
}

fe lc_eval(const cs_t *cs, const lc_t *a) {
  if (!cs->has_wit) return 0;
  fe r = a->k;
  for (uint32_t i = 0; i < a->n; i++) r = fe_add(r, fe_mul(a->c[i], cs_val(cs, a->w[i])));
  return r;
}

wire_t cs_free_wire(cs_t *cs, fe val) {
  if (cs->nF == cs->capF) {
    cs->capF *= 2;
    cs->valF = xrealloc(cs->valF, cs->capF * sizeof(fe));
  }
  cs->valF[cs->nF] = cs->has_wit ? val : 0;
  return WIRE_F | (wire_t)(cs->nF++);
}

static wire_t new_z(cs_t *cs, fe val) {
  if (cs->nZ == cs->capZ) {
    cs->capZ *= 2;
    cs->valZ = xrealloc(cs->valZ, cs->capZ * sizeof(fe));
  }
  if (cs->nZ >= 0x7FFFFFFFu) abort();
  cs->valZ[cs->nZ] = cs->has_wit ? val : 0;
  return (wire_t)(cs->nZ++);
}

wire_t cs_mul(cs_t *cs, const lc_t *a, const lc_t *b) {
  fe v = cs->has_wit ? fe_mul(lc_eval(cs, a), lc_eval(cs, b)) : 0;
  lcmat_push_lc(&cs->X, a);
  lcmat_push_lc(&cs->Y, b);
  return new_z(cs, v);
}

wire_t cs_bit(cs_t *cs, int bit) {
  if (cs->has_wit && bit != 0 && bit != 1) cs->bad = 1;
  wire_t u = (wire_t)cs->nZ; /* index of the wire about to be created */
  lcmat_push_term(&cs->X, u, 1);
  lcmat_end_row(&cs->X, 0);
  lcmat_push_term(&cs->Y, u, 1);
  lcmat_end_row(&cs->Y, 0);
  return new_z(cs, (fe)(bit & 1));
}

void cs_lin(cs_t *cs, const lc_t *a) { lcmat_push_lc(&cs->LIN, a); }

void cs_lin_begin(cs_t *cs) {
  if (cs->lin_open) abort();
  cs->lin_open = 1;
}
void cs_lin_term(cs_t *cs, wire_t w, fe c) {
  if (!cs->lin_open) abort();
  lcmat_push_term(&cs->LIN, w, c);
}
void cs_lin_end(cs_t *cs, fe k) {
  if (!cs->lin_open) abort();
  lcmat_end_row(&cs->LIN, k);
  cs->lin_open = 0;
}

static fe row_eval(const cs_t *cs, const lcmat_t *m, size_t i) {
  fe r = m->k[i];
  for (size_t t = m->off[i]; t < m->off[i + 1]; t++) r = fe_add(r, fe_mul(m->tc[t], cs_val(cs, m->tw[t])));
  return r;
}

size_t cs_check(const cs_t *cs, int verbose) {
  size_t bad = 0;
  if (!cs->has_wit) return (size_t)-1;
  for (size_t i = 0; i < cs->nZ; i++) {
    fe x = row_eval(cs, &cs->X, i), y = row_eval(cs, &cs->Y, i);
    if (fe_mul(x, y) != cs->valZ[i]) {
      if (verbose && bad < 10) fprintf(stderr, "mult constraint %zu violated\n", i);
      bad++;
    }
  }
  for (size_t j = 0; j < cs->LIN.n; j++) {
    if (row_eval(cs, &cs->LIN, j) != 0) {
      if (verbose && bad < 10) fprintf(stderr, "linear constraint %zu violated\n", j);
      bad++;
    }
  }
  return bad;
}

/* ---- LC helpers ---- */
static void lc_overflow(void) {
  fprintf(stderr, "LC overflow (LC_MAX=%d)\n", LC_MAX);
  abort();
}

void lc_wire(lc_t *a, wire_t w) {
  a->n = 1;
  a->k = 0;
  a->w[0] = w;
  a->c[0] = 1;
}

void lc_term(lc_t *a, wire_t w, fe c) {
  if (c == 0) return;
  for (uint32_t i = 0; i < a->n; i++) {
    if (a->w[i] == w) {
      a->c[i] = fe_add(a->c[i], c);
      if (a->c[i] == 0) { /* remove zero term */
        a->w[i] = a->w[a->n - 1];
        a->c[i] = a->c[a->n - 1];
        a->n--;
      }
      return;
    }
  }
  if (a->n >= LC_MAX) lc_overflow();
  a->w[a->n] = w;
  a->c[a->n] = c;
  a->n++;
}

void lc_add(lc_t *dst, const lc_t *a) {
  for (uint32_t i = 0; i < a->n; i++) lc_term(dst, a->w[i], a->c[i]);
  dst->k = fe_add(dst->k, a->k);
}

void lc_addc(lc_t *dst, const lc_t *a, fe c) {
  for (uint32_t i = 0; i < a->n; i++) lc_term(dst, a->w[i], fe_mul(a->c[i], c));
  dst->k = fe_add(dst->k, fe_mul(a->k, c));
}

void lc_copy(lc_t *dst, const lc_t *src) {
  dst->n = src->n;
  dst->k = src->k;
  memcpy(dst->w, src->w, src->n * sizeof(wire_t));
  memcpy(dst->c, src->c, src->n * sizeof(fe));
}
