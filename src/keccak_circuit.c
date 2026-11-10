/*
 * keccak_circuit.c -- Keccak-f[1600] permutation as an arithmetic circuit.
 *
 * theta: column parity C[x][z] of five bits via a 3-bit decomposition of their
 *        integer sum (3 booleanity constraints); D = C[x-1] xor rot(C[x+1],1)
 *        (1 mult); A' = A xor D (1 mult per state bit).
 * rho/pi: wire permutation (free).
 * chi:   out = a xor ((1-b) and c) = a + (c - bc) - 2 a (c - bc): 2 mults per bit,
 *        output materialized as a free wire.
 * iota:  constant XOR (linear).
 */
#include "keccak_circuit.h"
#include "gadgets.h"
#include <stdlib.h>
#include <string.h>

size_t keccak_circuit_perms = 0;

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

/* rho rotation offsets r[x][y] (FIPS 202, Table 2) */
static const int RHO[5][5] = {
    /* x=0 */ {0, 36, 3, 41, 18},
    /* x=1 */ {1, 44, 10, 45, 2},
    /* x=2 */ {62, 6, 43, 15, 61},
    /* x=3 */ {28, 55, 25, 21, 56},
    /* x=4 */ {27, 20, 39, 8, 14}};

#define IDX(x, y, z) ((((x) + 5 * (y)) << 6) | (z))

static uint64_t bitval(const cs_t *cs, const lc_t *a) { return cs->has_wit ? lc_eval(cs, a) : 0; }

void keccakf_circuit(cs_t *cs, lc_t *A) {
  lc_t *C = malloc(sizeof(lc_t) * 320);
  lc_t *D = malloc(sizeof(lc_t) * 320);
  lc_t *B = malloc(sizeof(lc_t) * 1600);
  lc_t tmp, t2, t3;
  keccak_circuit_perms++;
  for (int round = 0; round < 24; round++) {
    /* theta: column parities */
    for (int x = 0; x < 5; x++)
      for (int z = 0; z < 64; z++) {
        lc_zero(&tmp);
        uint64_t v = 0;
        for (int y = 0; y < 5; y++) {
          lc_add(&tmp, &A[IDX(x, y, z)]);
          v += bitval(cs, &A[IDX(x, y, z)]);
        }
        wire_t bits[3];
        g_bits(cs, &tmp, v, 3, bits); /* sum = p + 2 t0 + 4 t1 */
        lc_wire(&C[x * 64 + z], bits[0]);
      }
    for (int x = 0; x < 5; x++)
      for (int z = 0; z < 64; z++)
        g_xor(cs, &D[x * 64 + z], &C[((x + 4) % 5) * 64 + z], &C[((x + 1) % 5) * 64 + ((z + 63) % 64)]);
    for (int x = 0; x < 5; x++)
      for (int y = 0; y < 5; y++)
        for (int z = 0; z < 64; z++) g_xor(cs, &A[IDX(x, y, z)], &A[IDX(x, y, z)], &D[x * 64 + z]);
    /* rho + pi: B[y][2x+3y] = rot(A[x][y], r[x][y]) */
    for (int x = 0; x < 5; x++)
      for (int y = 0; y < 5; y++) {
        int X = y, Y = (2 * x + 3 * y) % 5, r = RHO[x][y];
        for (int z = 0; z < 64; z++) lc_copy(&B[IDX(X, Y, z)], &A[IDX(x, y, (z - r + 64) % 64)]);
      }
    /* chi */
    for (int x = 0; x < 5; x++)
      for (int y = 0; y < 5; y++)
        for (int z = 0; z < 64; z++) {
          const lc_t *a = &B[IDX(x, y, z)], *b = &B[IDX((x + 1) % 5, y, z)], *c = &B[IDX((x + 2) % 5, y, z)];
          g_mul(cs, &tmp, b, c);   /* tmp = b c */
          lc_copy(&t2, c);         /* t2 = c - b c = (1-b) c */
          lc_addc(&t2, &tmp, fe_neg(1));
          g_xor(cs, &t3, a, &t2);  /* out = a xor t2 */
          wire_t o = g_mat(cs, &t3);
          lc_wire(&A[IDX(x, y, z)], o);
        }
    /* iota */
    for (int z = 0; z < 64; z++)
      if ((RC[round] >> z) & 1) {
        lc_t *a = &A[IDX(0, 0, z)];
        lc_t n1;
        lc_const(&n1, 1);
        lc_addc(&n1, a, fe_neg(1));
        lc_copy(a, &n1);
      }
  }
  free(C);
  free(D);
  free(B);
}

void shake256_circuit(cs_t *cs, lc_t *out, size_t outbits, const lc_t *in, size_t inbits) {
  const size_t rate = SHAKE256_RATE_BYTES * 8;
  lc_t *S = malloc(sizeof(lc_t) * 1600);
  for (int i = 0; i < 1600; i++) lc_zero(&S[i]);
  size_t inbytes = inbits / 8;
  size_t nblocks = inbytes / SHAKE256_RATE_BYTES + 1;
  size_t total = nblocks * rate;
  int first = 1;
  for (size_t blk = 0; blk < nblocks; blk++) {
    for (size_t j = 0; j < rate; j++) {
      size_t pos = blk * rate + j; /* bit position in padded message */
      lc_t bit;
      if (pos < inbits) {
        lc_copy(&bit, &in[pos]);
      } else {
        /* padding: byte 0x1F right after the message, 0x80 in the last byte */
        size_t byte = pos / 8, b = pos % 8;
        unsigned v = 0;
        if (byte == inbytes) v |= 0x1F;
        if (byte == total / 8 - 1) v |= 0x80;
        lc_const(&bit, (v >> b) & 1);
      }
      if (lc_is_const(&bit)) {
        if (bit.k == 1) { /* S = 1 - S */
          lc_t n1;
          lc_const(&n1, 1);
          lc_addc(&n1, &S[j], fe_neg(1));
          lc_copy(&S[j], &n1);
        }
      } else if (first || lc_is_const(&S[j])) {
        if (lc_is_const(&S[j]) && S[j].k == 1) { /* 1 xor bit */
          lc_t n1;
          lc_const(&n1, 1);
          lc_addc(&n1, &bit, fe_neg(1));
          lc_copy(&S[j], &n1);
        } else if (lc_is_const(&S[j])) {
          lc_copy(&S[j], &bit);
        } else {
          g_xor(cs, &S[j], &S[j], &bit);
        }
      } else {
        g_xor(cs, &S[j], &S[j], &bit);
      }
    }
    first = 0;
    keccakf_circuit(cs, S);
  }
  size_t done = 0;
  while (done < outbits) {
    size_t take = outbits - done < rate ? outbits - done : rate;
    for (size_t j = 0; j < take; j++) lc_copy(&out[done + j], &S[j]);
    done += take;
    if (done < outbits) keccakf_circuit(cs, S);
  }
  free(S);
}
