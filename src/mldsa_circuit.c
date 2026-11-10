/*
 * mldsa_circuit.c -- the MOBS[ML-DSA] opening relation (O1)-(O8) as a circuit
 * over the Goldilocks field.
 *
 * NOTE: params.h defines single-letter macros (K, L, N, Q, D). They are only
 * used as ML-DSA parameters in this file; no local identifier uses these names.
 */
#include "mldsa_circuit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fips202.h"
#include "gadgets.h"
#include "keccak_circuit.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "rounding.h"

const uint8_t MOBS_DS_COM[MOBS_DS_BYTES] = {'M', 'O', 'B', 'S', '-', 'v', '1', '/', 'c', 'o', 'm', 'm', 'i', 't', 0, 0};
const uint8_t MOBS_DS_ISS[MOBS_DS_BYTES] = {'M', 'O', 'B', 'S', '-', 'v', '1', '/', 'i', 's', 's', 'u', 'e', 0, 0, 0};
const uint8_t MOBS_CTX_ML[MOBS_DS_BYTES] = {'M', 'O', 'B', 'S', '-', 'v', '1', '/', 'M', 'L', '-', 'D', 'S', 'A', 0, 0};

int32_t mobs_debug_c[256];

static unsigned bitlen(uint64_t x) {
  unsigned b = 0;
  while (x) { b++; x >>= 1; }
  return b;
}

static fe fe_of_i64(int64_t v) { return fe_from_i64(v); }
static int64_t i64_of_fe(fe v) { return v > FE_P / 2 ? -(int64_t)(FE_P - v) : (int64_t)v; }

/* Allocates nb witness bits holding v (< 2^nb) and returns their LC sum 2^i b_i. */
static void alloc_bits_lc(cs_t *cs, lc_t *out, uint64_t v, unsigned nb) {
  lc_zero(out);
  if (cs->has_wit && nb < 64 && (v >> nb)) cs->bad = 1;
  for (unsigned i = 0; i < nb; i++) {
    wire_t b = cs_bit(cs, cs->has_wit ? (int)((v >> i) & 1) : 0);
    lc_term(out, b, (fe)1 << i);
  }
}

/* out = LC of a value v in [0, bound]: nb = bitlen(bound) bits plus an upper check. */
static void bounded(cs_t *cs, lc_t *out, uint64_t v, uint64_t bound, unsigned nb) {
  alloc_bits_lc(cs, out, v, nb);
  lc_t up;
  lc_const(&up, (fe)bound);
  lc_addc(&up, out, fe_neg(1));
  g_bits(cs, &up, cs->has_wit ? bound - v : 0, nb, NULL);
  if (cs->has_wit && v > bound) cs->bad = 1;
}

/* ---------------- SampleInBall_B as a circuit (Lemma 6) ---------------- */
static void sampleinball_circuit(cs_t *cs, lc_t *cout, const lc_t *ctb) {
  const int has = cs->has_wit;
  const size_t SBITS = 1088 * MOBS_SIB_BLOCKS;
  const size_t NB = 136 * MOBS_SIB_BLOCKS - 8; /* candidate bytes */
  lc_t *S = malloc(sizeof(lc_t) * SBITS);
  shake256_circuit(cs, S, SBITS, ctb, 8 * CTILDEBYTES);

  lc_t *sg = malloc(sizeof(lc_t) * (TAU + 1));
  lc_t *nsg = malloc(sizeof(lc_t) * (TAU + 1));
  lc_t *acc_k = malloc(sizeof(lc_t) * (TAU + 1));
  wire_t *jt = malloc(sizeof(wire_t) * TAU * NB);
  size_t *jn = calloc(TAU, sizeof(size_t));
  for (int kk = 0; kk <= TAU; kk++) lc_const(&sg[kk], kk == 0);

  lc_t bv, ip, acc, tmp, d, arg, m1, v, nd, wv;
  for (size_t p = 0; p < NB; p++) {
    lc_zero(&bv);
    for (int b = 0; b < 8; b++) lc_addc(&bv, &S[8 * (8 + p) + b], (fe)1 << b);
    lc_const(&ip, 256 - TAU);
    for (int kk = 1; kk <= TAU; kk++) lc_addc(&ip, &sg[kk], (fe)kk);
    int accv = 0;
    if (has) {
      uint64_t bval = lc_eval(cs, &bv), ipv = lc_eval(cs, &ip), done = lc_eval(cs, &sg[TAU]);
      accv = (!done && bval <= ipv);
    }
    lc_wire(&acc, cs_bit(cs, accv));
    /* acc * done = 0 */
    g_mul(cs, &tmp, &acc, &sg[TAU]);
    if (!lc_is_const(&tmp)) cs_lin(cs, &tmp);
    /* d = ip - bv;  v = acc(2d+1) - d - 1;  notdone * v in [0, 256) */
    lc_copy(&d, &ip);
    lc_addc(&d, &bv, fe_neg(1));
    lc_zero(&arg);
    lc_addc(&arg, &d, 2);
    lc_addk(&arg, 1);
    g_mul(cs, &m1, &acc, &arg);
    lc_copy(&v, &m1);
    lc_addc(&v, &d, fe_neg(1));
    lc_addk(&v, fe_neg(1));
    lc_const(&nd, 1);
    lc_addc(&nd, &sg[TAU], fe_neg(1));
    g_mul(cs, &wv, &nd, &v);
    g_bits(cs, &wv, has ? lc_eval(cs, &wv) : 0, 8, NULL);
    /* transitions: a_k = sigma_k * acc; sigma'_k = sigma_k - a_k + a_{k-1} */
    for (int kk = 0; kk <= TAU; kk++) g_mul(cs, &acc_k[kk], &sg[kk], &acc);
    for (int kk = 0; kk <= TAU; kk++) {
      lc_copy(&nsg[kk], &sg[kk]);
      lc_addc(&nsg[kk], &acc_k[kk], fe_neg(1));
      if (kk > 0) lc_add(&nsg[kk], &acc_k[kk - 1]);
      if (!lc_is_const(&nsg[kk])) {
        wire_t w = g_mat(cs, &nsg[kk]);
        lc_wire(&nsg[kk], w);
      }
    }
    for (int kk = 0; kk <= TAU; kk++) lc_copy(&sg[kk], &nsg[kk]);
    /* selected byte for step k: a_k * byte */
    for (int kk = 0; kk < TAU; kk++)
      if (!lc_is_const(&acc_k[kk])) {
        g_mul(cs, &tmp, &acc_k[kk], &bv);
        jt[kk * NB + jn[kk]++] = tmp.w[0];
      }
  }
  /* all TAU positions must have been sampled */
  lc_copy(&tmp, &sg[TAU]);
  lc_addk(&tmp, fe_neg(1));
  cs_lin(cs, &tmp);

  /* j_k as free wires */
  wire_t *jw = malloc(sizeof(wire_t) * TAU);
  for (int kk = 0; kk < TAU; kk++) {
    fe val = 0;
    for (size_t t = 0; t < jn[kk]; t++) val = fe_add(val, cs_val(cs, jt[kk * NB + t]));
    jw[kk] = cs_free_wire(cs, val);
    cs_lin_begin(cs);
    for (size_t t = 0; t < jn[kk]; t++) cs_lin_term(cs, jt[kk * NB + t], 1);
    cs_lin_term(cs, jw[kk], fe_neg(1));
    cs_lin_end(cs, 0);
  }

  /* the TAU swap steps */
  lc_t *c = malloc(sizeof(lc_t) * 256);
  lc_t *F = malloc(sizeof(lc_t) * 256);
  for (int x = 0; x < 256; x++) lc_const(&c[x], 0);
  for (int kk = 0; kk < TAU; kk++) {
    int ik = 256 - TAU + kk;
    wire_t jb[8];
    lc_t jl;
    lc_wire(&jl, jw[kk]);
    g_bits(cs, &jl, has ? cs_val(cs, jw[kk]) : 0, 8, jb);
    /* one-hot F over 256 positions from the 8 bits */
    lc_const(&F[0], 1);
    size_t size = 1;
    for (int b = 0; b < 8; b++) {
      lc_t bl;
      lc_wire(&bl, jb[b]);
      for (size_t x = 0; x < size; x++) {
        g_mul(cs, &F[x + size], &F[x], &bl);
        lc_addc(&F[x], &F[x + size], fe_neg(1));
      }
      size *= 2;
    }
    /* R = c[j] = sum_{x <= ik} F[x] c[x] */
    fe rv = 0;
    wire_t *rt = malloc(sizeof(wire_t) * 256);
    int nrt = 0;
    for (int x = 0; x <= ik; x++) {
      if (lc_is_const(&c[x]) && c[x].k == 0) continue;
      g_mul(cs, &tmp, &F[x], &c[x]);
      rt[nrt++] = tmp.w[0];
      rv = fe_add(rv, lc_eval(cs, &tmp));
    }
    wire_t rw = cs_free_wire(cs, rv);
    cs_lin_begin(cs);
    for (int t = 0; t < nrt; t++) cs_lin_term(cs, rt[t], 1);
    cs_lin_term(cs, rw, fe_neg(1));
    cs_lin_end(cs, 0);
    free(rt);
    lc_wire(&c[ik], rw);
    /* c[x] <- c[x] + F[x] (sign - c[x]) for x <= ik */
    lc_t sl;
    lc_const(&sl, 1);
    lc_addc(&sl, &S[kk], fe_neg(2)); /* sign = 1 - 2 * signbit_k */
    for (int x = 0; x <= ik; x++) {
      lc_t diff;
      lc_copy(&diff, &sl);
      lc_addc(&diff, &c[x], fe_neg(1));
      g_mul(cs, &tmp, &F[x], &diff);
      lc_add(&tmp, &c[x]);
      wire_t w = g_mat(cs, &tmp);
      lc_wire(&c[x], w);
    }
  }
  for (int x = 0; x < 256; x++) {
    lc_copy(&cout[x], &c[x]);
    mobs_debug_c[x] = has ? (int32_t)i64_of_fe(lc_eval(cs, &c[x])) : 0;
  }
  free(S); free(sg); free(nsg); free(acc_k); free(jt); free(jn); free(jw); free(c); free(F);
}

/* ------------------------------ main builder ------------------------------ */
int mobs_build_circuit(cs_t *cs, const mobs_stmt_t *st, const mobs_wit_t *wit, mobs_circuit_stats_t *stats) {
  const int has = cs->has_wit;
  const size_t n = st->n;
  size_t perms0 = keccak_circuit_perms;
  if (n == 0 || n > MOBS_MAX_ATTRS) return -1;
  if (has && !wit) return -1;

  /* ---- public data: tr, A (coefficient form), t1 ---- */
  uint8_t rho[SEEDBYTES], tr[TRBYTES];
  polyveck t1;
  unpack_pk(rho, &t1, st->pk);
  shake256(tr, TRBYTES, st->pk, CRYPTO_PUBLICKEYBYTES);
  polyvecl mat[K];
  polyvec_matrix_expand(mat, rho);
  int32_t (*Acoef)[L][256] = malloc(sizeof(int32_t) * K * L * 256);
  {
    poly one;
    memset(&one, 0, sizeof(one));
    one.coeffs[0] = 1;
    poly_ntt(&one);
    for (int i = 0; i < K; i++)
      for (int j = 0; j < L; j++) {
        poly pp;
        poly_pointwise_montgomery(&pp, &mat[i].vec[j], &one);
        poly_reduce(&pp);
        poly_invntt_tomont(&pp);
        poly_reduce(&pp);
        poly_caddq(&pp);
        for (int t = 0; t < 256; t++) Acoef[i][j][t] = pp.coeffs[t];
      }
  }

  /* ---- witness decoding ---- */
  uint8_t ctil[CTILDEBYTES];
  polyvecl zv;
  polyveck hv;
  memset(ctil, 0, sizeof(ctil));
  memset(&zv, 0, sizeof(zv));
  memset(&hv, 0, sizeof(hv));
  if (has && unpack_sig(ctil, &zv, &hv, wit->sig)) cs->bad = 1;

  /* ---- witness bits: m, r, c~, h ---- */
  lc_t *mb = malloc(sizeof(lc_t) * n * 256);
  lc_t *rb = malloc(sizeof(lc_t) * 8 * MOBS_RBYTES);
  lc_t *cb = malloc(sizeof(lc_t) * 8 * CTILDEBYTES);
  wire_t *hb = malloc(sizeof(wire_t) * K * 256);
  g_witness_bytes(cs, mb, has ? wit->m : NULL, n * MOBS_ATTR_BYTES);
  g_witness_bytes(cs, rb, has ? wit->r : NULL, MOBS_RBYTES);
  g_witness_bytes(cs, cb, has ? ctil : NULL, CTILDEBYTES);
  int hsum = 0;
  for (int i = 0; i < K; i++)
    for (int t = 0; t < 256; t++) {
      int hbit = has ? hv.vec[i].coeffs[t] : 0;
      hsum += hbit;
      hb[i * 256 + t] = cs_bit(cs, hbit);
    }

  /* ---- (O1) disclosure ---- */
  for (size_t i = 0; i < n; i++)
    if (st->dmask[i])
      for (int b = 0; b < 256; b++) {
        lc_t e;
        lc_copy(&e, &mb[i * 256 + b]);
        lc_addk(&e, fe_neg((st->y[i * MOBS_ATTR_BYTES + b / 8] >> (b % 8)) & 1));
        cs_lin(cs, &e);
      }

  /* ---- (O2) commitment C = SHAKE256(DS_com || r || m) ---- */
  size_t cin_bits = 8 * (MOBS_DS_BYTES + MOBS_RBYTES + n * MOBS_ATTR_BYTES);
  lc_t *cin = malloc(sizeof(lc_t) * cin_bits);
  g_const_bytes(cin, MOBS_DS_COM, MOBS_DS_BYTES);
  for (size_t i = 0; i < 8 * MOBS_RBYTES; i++) lc_copy(&cin[8 * MOBS_DS_BYTES + i], &rb[i]);
  for (size_t i = 0; i < n * 256; i++) lc_copy(&cin[8 * (MOBS_DS_BYTES + MOBS_RBYTES) + i], &mb[i]);
  lc_t *Cb = malloc(sizeof(lc_t) * 8 * MOBS_CBYTES);
  shake256_circuit(cs, Cb, 8 * MOBS_CBYTES, cin, cin_bits);
  free(cin);

  /* ---- (O3) mu = SHAKE256(tr || 0 || |ctx| || ctx || DS_iss || C) ---- */
  size_t pre_bytes = TRBYTES + 2 + MOBS_DS_BYTES + MOBS_DS_BYTES;
  uint8_t *pre = malloc(pre_bytes);
  memcpy(pre, tr, TRBYTES);
  pre[TRBYTES] = 0;
  pre[TRBYTES + 1] = MOBS_DS_BYTES;
  memcpy(pre + TRBYTES + 2, MOBS_CTX_ML, MOBS_DS_BYTES);
  memcpy(pre + TRBYTES + 2 + MOBS_DS_BYTES, MOBS_DS_ISS, MOBS_DS_BYTES);
  size_t muin_bits = 8 * (pre_bytes + MOBS_CBYTES);
  lc_t *muin = malloc(sizeof(lc_t) * muin_bits);
  g_const_bytes(muin, pre, pre_bytes);
  for (size_t i = 0; i < 8 * MOBS_CBYTES; i++) lc_copy(&muin[8 * pre_bytes + i], &Cb[i]);
  lc_t *mu = malloc(sizeof(lc_t) * 8 * CRHBYTES);
  shake256_circuit(cs, mu, 8 * CRHBYTES, muin, muin_bits);
  free(muin);
  free(pre);

  /* ---- (O4) c = SampleInBall_B(c~) ---- */
  lc_t *cw = malloc(sizeof(lc_t) * 256);
  sampleinball_circuit(cs, cw, cb);
  int64_t cval[256];
  for (int s = 0; s < 256; s++) cval[s] = has ? i64_of_fe(lc_eval(cs, &cw[s])) : 0;

  /* ---- (O8a) z range, z as free wires ---- */
  const int64_t G1B = GAMMA1 - BETA;
  const uint64_t zbound = 2 * (uint64_t)(G1B - 1);
  const unsigned ZB = bitlen(zbound);
  wire_t *zw = malloc(sizeof(wire_t) * L * 256);
  int64_t (*zval)[256] = malloc(sizeof(int64_t) * L * 256);
  for (int j = 0; j < L; j++)
    for (int s = 0; s < 256; s++) {
      int64_t zc = has ? zv.vec[j].coeffs[s] : 0;
      zval[j][s] = zc;
      int64_t zz = zc + (G1B - 1);
      if (has && (zz < 0 || (uint64_t)zz > zbound)) cs->bad = 1;
      lc_t zl;
      bounded(cs, &zl, has ? (uint64_t)(zz < 0 ? 0 : zz) : 0, zbound, ZB);
      lc_addk(&zl, fe_neg((fe)(G1B - 1)));
      zw[j * 256 + s] = g_mat(cs, &zl);
    }

  /* ---- (O5)+(O6) per coefficient of w' ---- */
  const int64_t ALPHA = 2 * GAMMA2;
  const int64_t MM = (Q - 1) / ALPHA; /* 44 or 16 */
  const unsigned UB = bitlen((uint64_t)MM);
  const unsigned R0B = bitlen((uint64_t)(ALPHA - 1));
  const unsigned VB = bitlen((uint64_t)GAMMA2);
  const unsigned W1B = bitlen((uint64_t)(MM - 1));
  /* |w_int| bound -> kk range */
  const __int128 wbound = (__int128)L * 256 * (Q - 1) * (G1B - 1) + (__int128)TAU * 1023 * (1 << D);
  int64_t kkmax = (int64_t)(wbound / Q) + 2, KK_OFF = 1;
  while (KK_OFF <= kkmax) KK_OFF <<= 1;
  const unsigned KKB = bitlen((uint64_t)KK_OFF) + 1;
  lc_t *w1bits = malloc(sizeof(lc_t) * K * 256 * W1B);
  for (int i = 0; i < K; i++)
    for (int t = 0; t < 256; t++) {
      /* witness integer w_int */
      int64_t wint = 0;
      if (has) {
        for (int j = 0; j < L; j++)
          for (int s = 0; s < 256; s++) {
            int idx = t - s;
            int64_t a = idx >= 0 ? Acoef[i][j][idx] : -(int64_t)Acoef[i][j][idx + 256];
            wint += a * zval[j][s];
          }
        for (int s = 0; s < 256; s++) {
          int idx = t - s;
          int64_t a = idx >= 0 ? t1.vec[i].coeffs[idx] : -(int64_t)t1.vec[i].coeffs[idx + 256];
          wint -= a * ((int64_t)1 << D) * cval[s];
        }
      }
      int64_t rplus = ((wint % Q) + Q) % Q;
      int64_t kq = (wint - rplus) / Q;
      lc_t rp, kl;
      bounded(cs, &rp, has ? (uint64_t)rplus : 0, Q - 1, 23);
      alloc_bits_lc(cs, &kl, has ? (uint64_t)(kq + KK_OFF) : 0, KKB);
      /* big linear constraint: sum A z - 2^d t1 c - rplus - Q (kl - KK_OFF) = 0 */
      cs_lin_begin(cs);
      for (int j = 0; j < L; j++)
        for (int s = 0; s < 256; s++) {
          int idx = t - s;
          int64_t a = idx >= 0 ? Acoef[i][j][idx] : -(int64_t)Acoef[i][j][idx + 256];
          if (a) cs_lin_term(cs, zw[j * 256 + s], fe_of_i64(a));
        }
      fe kconst = fe_of_i64(Q * KK_OFF);
      for (int s = 0; s < 256; s++) {
        int idx = t - s;
        int64_t a = idx >= 0 ? t1.vec[i].coeffs[idx] : -(int64_t)t1.vec[i].coeffs[idx + 256];
        fe coef = fe_of_i64(-(a * ((int64_t)1 << D)));
        if (!coef) continue;
        for (uint32_t q2 = 0; q2 < cw[s].n; q2++) cs_lin_term(cs, cw[s].w[q2], fe_mul(coef, cw[s].c[q2]));
        kconst = fe_add(kconst, fe_mul(coef, cw[s].k));
      }
      for (uint32_t q2 = 0; q2 < rp.n; q2++) cs_lin_term(cs, rp.w[q2], fe_neg(rp.c[q2]));
      for (uint32_t q2 = 0; q2 < kl.n; q2++) cs_lin_term(cs, kl.w[q2], fe_neg(fe_mul(kl.c[q2], Q)));
      cs_lin_end(cs, kconst);

      /* Decompose(rplus) */
      int64_t r0 = rplus % ALPHA;
      if (r0 > GAMMA2) r0 -= ALPHA;
      int64_t u = (rplus - r0) / ALPHA;
      lc_t ul, r0l, tmp;
      bounded(cs, &ul, has ? (uint64_t)u : 0, (uint64_t)MM, UB);
      bounded(cs, &r0l, has ? (uint64_t)(r0 + GAMMA2 - 1) : 0, (uint64_t)(ALPHA - 1), R0B);
      lc_addk(&r0l, fe_neg((fe)(GAMMA2 - 1))); /* r0l = r0 */
      lc_copy(&tmp, &rp);
      lc_addc(&tmp, &ul, fe_neg((fe)ALPHA));
      lc_addc(&tmp, &r0l, fe_neg(1));
      cs_lin(cs, &tmp); /* rplus = ALPHA u + r0 */
      lc_t e, r1, r0p;
      g_eq_const(cs, &e, &ul, (fe)MM);
      lc_copy(&r1, &ul);
      lc_addc(&r1, &e, fe_neg((fe)MM));
      lc_copy(&r0p, &r0l);
      lc_addc(&r0p, &e, fe_neg(1));
      int64_t ev = (u == MM), r1v = ev ? 0 : u, r0pv = r0 - ev;
      /* s = [r0' > 0] */
      int sv = r0pv > 0;
      lc_t sl, sr, vv;
      lc_wire(&sl, cs_bit(cs, has ? sv : 0));
      g_mul(cs, &sr, &sl, &r0p);
      lc_zero(&vv);
      lc_addc(&vv, &sr, 2);
      lc_addc(&vv, &sl, fe_neg(1));
      lc_addc(&vv, &r0p, fe_neg(1));
      g_bits(cs, &vv, has ? (uint64_t)(sv ? r0pv - 1 : -r0pv) : 0, VB, NULL);
      /* UseHint */
      int hbit = has ? hv.vec[i].coeffs[t] : 0;
      lc_t hl, e1, e0, argl, t1v, del, hd, w1;
      lc_wire(&hl, hb[i * 256 + t]);
      g_eq_const(cs, &e1, &r1, (fe)(MM - 1));
      g_eq_const(cs, &e0, &r1, 0);
      lc_const(&argl, 2);
      lc_addc(&argl, &e1, fe_neg((fe)MM));
      lc_addc(&argl, &e0, fe_neg((fe)MM));
      g_mul(cs, &t1v, &sl, &argl);
      lc_copy(&del, &t1v);
      lc_addk(&del, fe_neg(1));
      lc_addc(&del, &e0, (fe)MM);
      g_mul(cs, &hd, &hl, &del);
      lc_copy(&w1, &r1);
      lc_add(&w1, &hd);
      int64_t w1v = r1v;
      if (hbit) w1v = sv ? (r1v == MM - 1 ? 0 : r1v + 1) : (r1v == 0 ? MM - 1 : r1v - 1);
      if (has && w1v != use_hint((int32_t)rplus, (unsigned)hbit)) cs->bad = 1;
      wire_t wb[8];
      g_bits(cs, &w1, has ? (uint64_t)w1v : 0, W1B, wb);
      for (unsigned b = 0; b < W1B; b++) lc_wire(&w1bits[(i * 256 + t) * W1B + b], wb[b]);
    }

  /* ---- (O7) c~ = SHAKE256(mu || w1Encode(w1)) ---- */
  size_t hin_bits = 8 * CRHBYTES + (size_t)K * 256 * W1B;
  lc_t *hin = malloc(sizeof(lc_t) * hin_bits);
  for (size_t i = 0; i < 8 * CRHBYTES; i++) lc_copy(&hin[i], &mu[i]);
  for (size_t i = 0; i < (size_t)K * 256 * W1B; i++) lc_copy(&hin[8 * CRHBYTES + i], &w1bits[i]);
  lc_t *c2 = malloc(sizeof(lc_t) * 8 * CTILDEBYTES);
  shake256_circuit(cs, c2, 8 * CTILDEBYTES, hin, hin_bits);
  for (size_t i = 0; i < 8 * CTILDEBYTES; i++) {
    lc_t e;
    lc_copy(&e, &c2[i]);
    lc_addc(&e, &cb[i], fe_neg(1));
    cs_lin(cs, &e);
  }
  free(hin);
  free(c2);

  /* ---- (O8b) wt(h) <= omega ---- */
  {
    const unsigned HB = bitlen(OMEGA);
    if (has && hsum > OMEGA) cs->bad = 1;
    uint64_t slack = has ? (uint64_t)(OMEGA - hsum) : 0;
    wire_t sb[16];
    for (unsigned b = 0; b < HB; b++) sb[b] = cs_bit(cs, has ? (int)((slack >> b) & 1) : 0);
    cs_lin_begin(cs);
    for (int i = 0; i < K * 256; i++) cs_lin_term(cs, hb[i], 1);
    for (unsigned b = 0; b < HB; b++) cs_lin_term(cs, sb[b], (fe)1 << b);
    cs_lin_end(cs, fe_neg(OMEGA));
  }

  if (stats) {
    stats->perms = keccak_circuit_perms - perms0;
    stats->mults = cs->nZ;
    stats->free_wires = cs->nF;
    stats->lin = cs->LIN.n;
  }
  free(Acoef); free(mb); free(rb); free(cb); free(hb); free(Cb); free(mu); free(cw);
  free(zw); free(zval); free(w1bits);
  return 0;
}
