/*
 * xof.c -- cSHAKE256(X, L, N = "", S) = KECCAK[512](bytepad(encode_string(N) ||
 *          encode_string(S), 136) || X || 00, L)            (NIST SP 800-185, Sect. 3)
 */
#include "xof.h"
#include <stdlib.h>
#include <string.h>

static size_t left_encode(uint8_t *out, uint64_t x) {
  uint8_t tmp[8];
  size_t n = 0;
  do {
    tmp[n++] = (uint8_t)x;
    x >>= 8;
  } while (x);
  out[0] = (uint8_t)n;
  for (size_t i = 0; i < n; i++) out[1 + i] = tmp[n - 1 - i];
  return n + 1;
}

void mobs_cshake256_init(keccak_state *s, const char *custom) {
  uint8_t blk[SHAKE256_RATE];
  size_t sl = strlen(custom), p = 0;
  if (sl > 120) abort();
  memset(blk, 0, sizeof(blk));
  p += left_encode(blk + p, SHAKE256_RATE); /* bytepad: left_encode(w) */
  p += left_encode(blk + p, 0);             /* encode_string(N = "") */
  p += left_encode(blk + p, 8 * (uint64_t)sl); /* encode_string(S) */
  memcpy(blk + p, custom, sl);
  shake256_init(s);
  shake256_absorb(s, blk, SHAKE256_RATE); /* exactly one rate block */
}

void mobs_cshake256_finalize(keccak_state *s) {
  /* same as keccak_finalize(..., SHAKE256_RATE, 0x04) in fips202.c */
  s->s[s->pos / 8] ^= (uint64_t)0x04 << (8 * (s->pos % 8));
  s->s[SHAKE256_RATE / 8 - 1] ^= 1ULL << 63;
  s->pos = SHAKE256_RATE;
}

void mobs_cshake256(uint8_t *out, size_t outlen, const char *custom, const uint8_t *in, size_t inlen) {
  keccak_state s;
  mobs_cshake256_init(&s, custom);
  shake256_absorb(&s, in, inlen);
  mobs_cshake256_finalize(&s);
  shake256_squeeze(out, outlen, &s);
}
