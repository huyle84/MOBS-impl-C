/*
 * cs.h -- constraint system in Ligero-native form.
 *
 * Wires:
 *   Z-wires  (index i)            : output of the i-th multiplication constraint.
 *   F-wires  (index j | WIRE_F)   : "free" wires (only constrained linearly).
 * Constraints:
 *   multiplication i :  LC_x(i)(w) * LC_y(i)(w) = Z_i
 *   linear j         :  sum_t c_t * w_t + k_j = 0
 * A linear combination (LC) is sum_t c_t * w_t + k with field coefficients.
 *
 * The same builder code runs for the prover (with witness values) and for the
 * verifier (structure only). Gadgets never branch on witness values, so both
 * runs produce identical constraint systems.
 */
#ifndef MOBS_CS_H
#define MOBS_CS_H

#include <stddef.h>
#include <stdint.h>
#include "field.h"

typedef uint32_t wire_t;
#define WIRE_F 0x80000000u
#define WIRE_IS_F(w) (((w) & WIRE_F) != 0)
#define WIRE_IDX(w) ((w) & 0x7FFFFFFFu)

#define LC_MAX 96
typedef struct {
  uint32_t n;
  fe k;
  wire_t w[LC_MAX];
  fe c[LC_MAX];
} lc_t;

typedef struct {
  size_t n, cap;
  size_t *off;  /* n+1 offsets */
  size_t nt, capt;
  wire_t *tw;
  fe *tc;
  fe *k;        /* constant per row */
} lcmat_t;

typedef struct {
  int has_wit;
  int bad;      /* set if a witness value violates an expected range (prover-side debug) */
  size_t nF, capF;
  fe *valF;
  size_t nZ, capZ;
  fe *valZ;
  lcmat_t X, Y; /* row i = LC_x(i), LC_y(i) */
  lcmat_t LIN;  /* linear constraints */
  int lin_open; /* builder state for big linear constraints */
} cs_t;

void cs_init(cs_t *cs, int has_wit);
void cs_free(cs_t *cs);

wire_t cs_free_wire(cs_t *cs, fe val);
wire_t cs_mul(cs_t *cs, const lc_t *a, const lc_t *b);
wire_t cs_bit(cs_t *cs, int bit);          /* booleanity: u*u = u, u is the output */
void cs_lin(cs_t *cs, const lc_t *a);      /* a == 0 */
/* big linear constraints (arbitrary number of terms) */
void cs_lin_begin(cs_t *cs);
void cs_lin_term(cs_t *cs, wire_t w, fe c);
void cs_lin_end(cs_t *cs, fe k);

fe cs_val(const cs_t *cs, wire_t w);
fe lc_eval(const cs_t *cs, const lc_t *a);
/* number of violated constraints (requires witness) */
size_t cs_check(const cs_t *cs, int verbose);

/* ---- LC helpers ---- */
static inline void lc_zero(lc_t *a) { a->n = 0; a->k = 0; }
static inline void lc_const(lc_t *a, fe k) { a->n = 0; a->k = k; }
void lc_wire(lc_t *a, wire_t w);
void lc_term(lc_t *a, wire_t w, fe c);             /* a += c*w */
void lc_add(lc_t *dst, const lc_t *a);             /* dst += a */
void lc_addc(lc_t *dst, const lc_t *a, fe c);      /* dst += c*a */
void lc_copy(lc_t *dst, const lc_t *src);
static inline void lc_addk(lc_t *a, fe k) { a->k = fe_add(a->k, k); }
static inline int lc_is_const(const lc_t *a) { return a->n == 0; }

#endif
