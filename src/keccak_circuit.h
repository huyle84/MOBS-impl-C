/*
 * keccak_circuit.h -- Keccak-f[1600] and SHAKE256 as arithmetic circuits over F_p.
 *
 * State bits are LCs with values in {0,1}. Bit i of the state is bit (i mod 64)
 * of lane i/64 (lane index x + 5y), i.e. FIPS 202 little-endian convention:
 * byte b of the sponge input occupies state bits 8b..8b+7 (LSB first).
 *
 * Cost per round: 6080 multiplications, 1600 free wires.
 */
#ifndef MOBS_KECCAK_CIRCUIT_H
#define MOBS_KECCAK_CIRCUIT_H

#include "cs.h"

#define SHAKE256_RATE_BYTES 136

void keccakf_circuit(cs_t *cs, lc_t *state /* [1600] */);

/* SHAKE256 on an input of inbits bits (multiple of 8, LSB-first per byte).
 * Writes outbits output bits. Each input bit is an LC (constant or bit-valued). */
void shake256_circuit(cs_t *cs, lc_t *out, size_t outbits, const lc_t *in, size_t inbits);

/* statistics */
extern size_t keccak_circuit_perms;

#endif
