/*
 * xof.h -- cSHAKE256 (NIST SP 800-185) on top of the reference FIPS 202 code.
 *
 * Every random-oracle call of the NIZK (Fiat-Shamir transcript, Merkle leaves
 * and nodes, statement digest) uses cSHAKE256 with N = "" and a fixed,
 * non-empty customization string S. cSHAKE256 then pads with the domain suffix
 * 00 (first padding byte 0x04) instead of SHAKE256's 1111 (0x1F), so these
 * calls are separated, at the level of the permutation input, from every
 * SHAKE256 evaluation inside the proven statement (commitment, mu, c~,
 * SampleInBall). This realizes the requirement of the manuscript that the
 * NIZK's random oracle be domain-separated from all hashes in the statement.
 *
 * Usage: mobs_cshake256_init(&s, "S"); shake256_absorb(&s, ...)*;
 *        mobs_cshake256_finalize(&s); shake256_squeeze(out, len, &s)*.
 */
#ifndef MOBS_XOF_H
#define MOBS_XOF_H

#include <stddef.h>
#include <stdint.h>
#include "fips202.h"

/* customization strings must be at most 120 bytes */
void mobs_cshake256_init(keccak_state *s, const char *custom);
void mobs_cshake256_finalize(keccak_state *s);
/* one-shot helper */
void mobs_cshake256(uint8_t *out, size_t outlen, const char *custom, const uint8_t *in, size_t inlen);

#endif
