/*
 * gadgets.h -- reusable circuit gadgets over the Ligero constraint system.
 */
#ifndef MOBS_GADGETS_H
#define MOBS_GADGETS_H

#include "cs.h"

/* Decompose LC a into nb bits (little-endian). In witness mode, aval is the
 * integer value of a (must be < 2^nb, otherwise cs->bad is set). Adds the
 * constraint a = sum 2^i b_i. bits_out may be NULL. */
void g_bits(cs_t *cs, const lc_t *a, uint64_t aval, unsigned nb, wire_t *bits_out);

/* XOR of two bit-valued LCs: out = a + b - 2ab (one multiplication). */
void g_xor(cs_t *cs, lc_t *out, const lc_t *a, const lc_t *b);

/* e = [a == k] for an LC a; returns e as an LC (two multiplications, one free wire). */
void g_eq_const(cs_t *cs, lc_t *e_out, const lc_t *a, fe k);

/* Materialize an LC as a single free wire (one linear constraint). */
wire_t g_mat(cs_t *cs, const lc_t *a);

/* Product of two LCs returned as an LC (wrapper around cs_mul). */
void g_mul(cs_t *cs, lc_t *out, const lc_t *a, const lc_t *b);

/* Bits of a byte string as fresh witness bits (booleanity-checked). */
void g_witness_bytes(cs_t *cs, lc_t *bits_out, const uint8_t *bytes, size_t nbytes);
/* Constant bits of a public byte string */
void g_const_bytes(lc_t *bits_out, const uint8_t *bytes, size_t nbytes);

#endif
