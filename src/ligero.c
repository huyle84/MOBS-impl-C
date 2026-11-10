/*
 * ligero.c -- non-interactive Ligero argument (prover and verifier).
 *
 * Protocol (one commitment round, three parallel tests, one query round):
 *   1. P encodes every data row r as a codeword U_r = (p_r(eta))_{eta in L}, where
 *      p_r has degree < K, p_r(w_K^j) = row value for j < ell and random for the
 *      tpad padding points. P adds masking rows:
 *        u'_s (deg < K)                                  for the interleaved test,
 *        q'_s (deg < 2K-1, sum over H equal to 0)        for the linear test,
 *        p'_s (deg < 2K-1, vanishing on the first ell points of H) for the quadratic test,
 *      and commits to the n columns with a salted SHAKE256 Merkle tree.
 *   2. Challenges rI, rL, rQ are derived from the transcript (statement, label, root).
 *   3. P sends   w_s = sum_r rI_{s,r} p_r + u'_s                       (K coefficients)
 *                q_s = sum_r R_{s,r} p_r + q'_s                         (2K-1 coefficients)
 *                p_s = sum_rho rQ_{s,rho} (p_X p_Y - p_Z)_rho + p'_s    (2K-1 coefficients)
 *      where R_{s,r} interpolates the random linear combination of all linear constraints.
 *   4. t column indices are derived from the transcript; P opens those columns.
 *   V checks: Merkle paths; sum_H q_s = target; p_s vanishes on the first ell points of H;
 *   and consistency of w_s, q_s, p_s with the opened columns.
 */
#include "ligero.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fips202.h"
#include "randombytes.h"
#include "xof.h"

/* Merkle digest and salt length: 2*lambda bits (collision resistance lambda bits),
 * i.e. 32 / 48 / 64 bytes for lambda = 128 / 192 / 256. */
#define HBMAX 64
static unsigned hb_of(const lg_params_t *P) { return P->lambda <= 128 ? 32 : (P->lambda <= 192 ? 48 : 64); }
static const uint8_t MAGIC[8] = {'M', 'O', 'B', 'S', 'L', 'G', '0', '2'};

static double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ------------------------------ parameters ------------------------------ */
static unsigned derive_t(const lg_params_t *P) {
  double K = (double)(1u << P->logK), n = K * (double)(1u << P->logrho);
  double d = n - K + 1, e = floor((d - 1) / 4);
  double per = -log2(1.0 - e / n);
  return (unsigned)ceil((double)P->lambda / per);
}

void lg_params_level(lg_params_t *P, unsigned lambda) {
  /* per-repetition errors: interleaved test (e+1)/|F| ~ 2^-50.4 for K = 2^14, rate 1/4;
   * linear and quadratic tests 1/|F| = 2^-64 */
  P->logK = 14;
  P->logrho = 2;
  P->lambda = lambda;
  P->t = derive_t(P);
  P->tpad = 256;
  while (P->tpad < P->t) P->tpad += 256;
  double K = (double)(1u << P->logK), n = K * 4, e = floor((n - K) / 4);
  double errI = -log2((e + 1) / 18446744069414584321.0);
  P->sI = (unsigned)ceil(lambda / errI);
  P->sL = P->sQ = (lambda + 63) / 64;
}

void lg_params_default(lg_params_t *P) { lg_params_level(P, 128); }

void lg_params_test(lg_params_t *P) {
  P->logK = 8;
  P->logrho = 2;
  P->tpad = 64;
  P->sI = 1;
  P->sL = 1;
  P->sQ = 1;
  P->lambda = 12;
  P->t = derive_t(P);
}

double lg_column_soundness_bits(const lg_params_t *P) {
  double K = (double)(1u << P->logK), n = K * (double)(1u << P->logrho);
  double d = n - K + 1, e = floor((d - 1) / 4);
  return P->t * log2(1.0 - e / n);
}

/* ------------------------------ layout ------------------------------ */
typedef struct {
  size_t K, n, ell, tpad, nF, nZ, FR, ZR, R, RT, slots;
  unsigned logK, logn;
  size_t mI, mL, mQ; /* first masking row of each kind */
} layout_t;

static int mk_layout(layout_t *Ly, const cs_t *cs, const lg_params_t *P) {
  if (P->t > P->tpad || P->tpad >= (1u << P->logK)) return -1;
  Ly->logK = P->logK;
  Ly->logn = P->logK + P->logrho;
  Ly->K = (size_t)1 << P->logK;
  Ly->n = Ly->K << P->logrho;
  Ly->tpad = P->tpad;
  Ly->ell = Ly->K - P->tpad;
  Ly->nF = cs->nF;
  Ly->nZ = cs->nZ;
  Ly->FR = (Ly->nF + Ly->ell - 1) / Ly->ell;
  Ly->ZR = (Ly->nZ + Ly->ell - 1) / Ly->ell;
  if (Ly->ZR == 0) Ly->ZR = 1;
  Ly->R = Ly->FR + 3 * Ly->ZR;
  Ly->mI = Ly->R;
  Ly->mL = Ly->mI + P->sI;
  Ly->mQ = Ly->mL + P->sL;
  Ly->RT = Ly->mQ + P->sQ;
  Ly->slots = Ly->R * Ly->ell;
  return 0;
}

static inline size_t pos_w(const layout_t *Ly, wire_t w) {
  return WIRE_IS_F(w) ? WIRE_IDX(w) : Ly->FR * Ly->ell + w;
}
static inline size_t pos_x(const layout_t *Ly, size_t i) { return (Ly->FR + Ly->ZR) * Ly->ell + i; }
static inline size_t pos_y(const layout_t *Ly, size_t i) { return (Ly->FR + 2 * Ly->ZR) * Ly->ell + i; }
static inline size_t row_z(const layout_t *Ly, size_t rho) { return Ly->FR + rho; }
static inline size_t row_x(const layout_t *Ly, size_t rho) { return Ly->FR + Ly->ZR + rho; }
static inline size_t row_y(const layout_t *Ly, size_t rho) { return Ly->FR + 2 * Ly->ZR + rho; }

/* ------------------------------ randomness / XOF ------------------------------ */
static void rand_fe(fe *out, size_t cnt) {
  uint8_t buf[8 * 256];
  size_t i = 0;
  while (i < cnt) {
    randombytes(buf, sizeof(buf));
    for (size_t j = 0; j < 256 && i < cnt; j++) {
      uint64_t v = 0;
      for (int b = 0; b < 8; b++) v |= (uint64_t)buf[8 * j + b] << (8 * b);
      if (v < FE_P) out[i++] = v;
    }
  }
}

typedef struct {
  keccak_state st;
  uint8_t buf[8 * SHAKE256_RATE];
  size_t pos;
} xof_t;

static void xof_refill(xof_t *x) {
  shake256_squeeze(x->buf, sizeof(x->buf), &x->st);
  x->pos = 0;
}
static uint64_t xof_u64(xof_t *x) {
  if (x->pos + 8 > sizeof(x->buf)) xof_refill(x);
  uint64_t v = 0;
  for (int b = 0; b < 8; b++) v |= (uint64_t)x->buf[x->pos + b] << (8 * b);
  x->pos += 8;
  return v;
}
static fe xof_fe(xof_t *x) {
  for (;;) {
    uint64_t v = xof_u64(x);
    if (v < FE_P) return v;
  }
}

typedef struct {
  keccak_state st;
} transcript_t;

static void tr_absorb(transcript_t *T, const char *lab, const uint8_t *d, size_t len) {
  uint8_t hdr[9];
  size_t ll = strlen(lab);
  hdr[0] = (uint8_t)ll;
  for (int b = 0; b < 8; b++) hdr[1 + b] = (uint8_t)((uint64_t)len >> (8 * b));
  shake256_absorb(&T->st, hdr, 1);
  shake256_absorb(&T->st, (const uint8_t *)lab, ll);
  shake256_absorb(&T->st, hdr + 1, 8);
  if (len) shake256_absorb(&T->st, d, len);
}
/* All NIZK random-oracle calls use cSHAKE256 with distinct customization strings
 * (see xof.h): FS transcript, Merkle leaves, Merkle nodes. */
#define CS_FS "MOBS-Ligero-v1/FS"
#define CS_LEAF "MOBS-Ligero-v1/leaf"
#define CS_NODE "MOBS-Ligero-v1/node"
static void tr_init(transcript_t *T) { mobs_cshake256_init(&T->st, CS_FS); }
static void tr_xof(const transcript_t *T, const char *lab, unsigned idx, xof_t *x) {
  x->st = T->st;
  transcript_t tmp;
  tmp.st = x->st;
  uint8_t ib[4] = {(uint8_t)idx, (uint8_t)(idx >> 8), (uint8_t)(idx >> 16), (uint8_t)(idx >> 24)};
  tr_absorb(&tmp, lab, ib, 4);
  x->st = tmp.st;
  mobs_cshake256_finalize(&x->st);
  x->pos = sizeof(x->buf);
}

/* ------------------------------ serialization ------------------------------ */
static void put_u32(uint8_t *p, uint32_t v) {
  for (int b = 0; b < 4; b++) p[b] = (uint8_t)(v >> (8 * b));
}
static void put_fe(uint8_t *p, fe v) {
  for (int b = 0; b < 8; b++) p[b] = (uint8_t)(v >> (8 * b));
}
static int get_fe(const uint8_t *p, fe *v) {
  uint64_t x = 0;
  for (int b = 0; b < 8; b++) x |= (uint64_t)p[b] << (8 * b);
  if (x >= FE_P) return -1;
  *v = x;
  return 0;
}

#define HDR_FIELDS 11
#define HDR_BYTES_MAX (8 + 4 * HDR_FIELDS + HBMAX)
static size_t hdr_bytes(unsigned HB) { return 8 + 4 * HDR_FIELDS + HB; }
static void write_header(uint8_t *h, const lg_params_t *P, const layout_t *Ly) {
  memcpy(h, MAGIC, 8);
  uint32_t f[HDR_FIELDS] = {P->lambda, P->logK, P->logrho, P->tpad, P->t, P->sI, P->sL, P->sQ, (uint32_t)Ly->RT,
                            (uint32_t)Ly->nF, (uint32_t)Ly->nZ};
  for (int i = 0; i < HDR_FIELDS; i++) put_u32(h + 8 + 4 * i, f[i]);
}

static size_t proof_size(const lg_params_t *P, const layout_t *Ly) {
  size_t polys = (size_t)P->sI * Ly->K + (size_t)(P->sL + P->sQ) * (2 * Ly->K - 1);
  const unsigned HB = hb_of(P);
  size_t open = (size_t)P->t * (HB + Ly->RT * 8 + (size_t)Ly->logn * HB);
  return hdr_bytes(HB) + polys * 8 + open;
}

/* ------------------------------ Merkle tree ------------------------------ */
/* Prefix states (customization block already absorbed), computed once per call
 * of lg_prove / lg_verify. */
typedef struct {
  keccak_state leaf, node;
  unsigned HB;
} mk_ctx_t;
static void mk_init(mk_ctx_t *M, unsigned HB) {
  mobs_cshake256_init(&M->leaf, CS_LEAF);
  mobs_cshake256_init(&M->node, CS_NODE);
  M->HB = HB;
}
/* leaf = cSHAKE256(salt || column, "MOBS-Ligero-v1/leaf"), HB bytes */
static void leaf_hash(uint8_t *out, const mk_ctx_t *M, const uint8_t *salt, const fe *col, size_t RT, uint8_t *scratch) {
  keccak_state s = M->leaf;
  shake256_absorb(&s, salt, M->HB);
  for (size_t r = 0; r < RT; r++) put_fe(scratch + 8 * r, col[r]);
  shake256_absorb(&s, scratch, 8 * RT);
  mobs_cshake256_finalize(&s);
  shake256_squeeze(out, M->HB, &s);
}
/* node = cSHAKE256(left || right, "MOBS-Ligero-v1/node"), HB bytes */
static void node_hash(uint8_t *out, const mk_ctx_t *M, const uint8_t *l, const uint8_t *r) {
  keccak_state s = M->node;
  shake256_absorb(&s, l, M->HB);
  shake256_absorb(&s, r, M->HB);
  mobs_cshake256_finalize(&s);
  shake256_squeeze(out, M->HB, &s);
}

/* ------------------------------ shared helpers ------------------------------ */
static fe lcrow_eval(const cs_t *cs, const lcmat_t *m, size_t i) {
  fe r = m->k[i];
  for (size_t t = m->off[i]; t < m->off[i + 1]; t++) r = fe_add(r, fe_mul(m->tc[t], cs_val(cs, m->tw[t])));
  return r;
}

/* Random linear combination of all linear constraints:
 * cvec (length slots) and target T such that  <cvec, v> = T  for a valid v. */
static fe linear_combination(const cs_t *cs, const layout_t *Ly, xof_t *x, fe *cvec) {
  fe T = 0;
  memset(cvec, 0, Ly->slots * sizeof(fe));
  const lcmat_t *Lm = &cs->LIN;
  for (size_t j = 0; j < Lm->n; j++) {
    fe r = xof_fe(x);
    for (size_t t = Lm->off[j]; t < Lm->off[j + 1]; t++) {
      size_t p = pos_w(Ly, Lm->tw[t]);
      cvec[p] = fe_add(cvec[p], fe_mul(r, Lm->tc[t]));
    }
    T = fe_sub(T, fe_mul(r, Lm->k[j]));
  }
  for (int which = 0; which < 2; which++) {
    const lcmat_t *M = which ? &cs->Y : &cs->X;
    for (size_t i = 0; i < M->n; i++) {
      fe r = xof_fe(x);
      size_t px = which ? pos_y(Ly, i) : pos_x(Ly, i);
      cvec[px] = fe_add(cvec[px], r);
      for (size_t t = M->off[i]; t < M->off[i + 1]; t++) {
        size_t p = pos_w(Ly, M->tw[t]);
        cvec[p] = fe_sub(cvec[p], fe_mul(r, M->tc[t]));
      }
      T = fe_add(T, fe_mul(r, M->k[i]));
    }
  }
  return T;
}

/* Evaluate the interpolant of (row values on the first ell points of H, zero on
 * the padding points) on the coset L. buf has K entries, out has n entries. */
static void row_poly_on_L(fe *out, const fe *vals, const layout_t *Ly, fe *buf) {
  memcpy(buf, vals, Ly->ell * sizeof(fe));
  memset(buf + Ly->ell, 0, Ly->tpad * sizeof(fe));
  fe_intt(buf, Ly->logK);
  fe_coset_eval(out, buf, Ly->K, FE_GEN, Ly->logn);
}

static fe eta(const layout_t *Ly, size_t j) { return fe_mul(FE_GEN, fe_pow(fe_root_of_unity(Ly->logn), j)); }

/* ================================== PROVER ================================== */
int lg_prove(const cs_t *cs, const lg_params_t *P, const uint8_t *stmt, size_t stmtlen, const uint8_t *label,
             size_t labellen, uint8_t **proof, size_t *prooflen, int allow_unsat, lg_stats_t *stats) {
  double t0 = now();
  if (!cs->has_wit) return -1;
  if (!allow_unsat && cs_check(cs, 0) != 0) return -2;
  layout_t Ly;
  if (mk_layout(&Ly, cs, P)) return -1;
  const size_t K = Ly.K, n = Ly.n, ell = Ly.ell;
  const unsigned HB = hb_of(P);
  const size_t HDR_BYTES = hdr_bytes(HB);

  /* 1. slot values */
  fe *V = calloc(Ly.slots, sizeof(fe));
  for (size_t j = 0; j < Ly.nF; j++) V[j] = cs->valF[j];
  for (size_t i = 0; i < Ly.nZ; i++) {
    V[Ly.FR * ell + i] = cs->valZ[i];
    V[pos_x(&Ly, i)] = lcrow_eval(cs, &cs->X, i);
    V[pos_y(&Ly, i)] = lcrow_eval(cs, &cs->Y, i);
  }

  /* 2. encode rows */
  fe *U = malloc(Ly.RT * n * sizeof(fe));
  fe *buf = malloc(2 * K * sizeof(fe));
  if (!U || !buf) {
    free(V); free(U); free(buf);
    return -3;
  }
  for (size_t r = 0; r < Ly.R; r++) {
    memcpy(buf, V + r * ell, ell * sizeof(fe));
    rand_fe(buf + ell, Ly.tpad);
    fe_intt(buf, Ly.logK);
    fe_coset_eval(U + r * n, buf, K, FE_GEN, Ly.logn);
  }
  free(V);
  for (unsigned s = 0; s < P->sI; s++) { /* u'_s */
    rand_fe(buf, K);
    fe_coset_eval(U + (Ly.mI + s) * n, buf, K, FE_GEN, Ly.logn);
  }
  fe *Bh = malloc(K * sizeof(fe));
  for (unsigned s = 0; s < P->sL + P->sQ; s++) { /* q'_s and p'_s */
    int quad = s >= P->sL;
    fe *A = buf; /* buf has 2K entries: coefficients of A + (X^K - 1) B */
    if (!quad) {
      rand_fe(A, K);
      A[0] = 0; /* sum over H of A equals K * A_0 */
    } else {
      memset(A, 0, ell * sizeof(fe));
      rand_fe(A + ell, Ly.tpad);
      fe_intt(A, Ly.logK); /* A vanishes on the first ell points of H */
    }
    rand_fe(Bh, K - 1);
    for (size_t i = 0; i < K - 1; i++) {
      A[i] = fe_sub(A[i], Bh[i]);
      A[K + i] = Bh[i];
    }
    fe_coset_eval(U + (quad ? Ly.mQ + (s - P->sL) : Ly.mL + s) * n, A, 2 * K - 1, FE_GEN, Ly.logn);
  }
  free(Bh);

  /* 3. Merkle commitment over columns */
  mk_ctx_t MK;
  mk_init(&MK, HB);
  uint8_t *salts = malloc(n * HB);
  randombytes(salts, n * HB);
  uint8_t *tree = malloc(2 * n * HB);
  fe *col = malloc(Ly.RT * sizeof(fe));
  uint8_t *scratch = malloc(8 * Ly.RT);
  for (size_t j = 0; j < n; j++) {
    for (size_t r = 0; r < Ly.RT; r++) col[r] = U[r * n + j];
    leaf_hash(tree + (n + j) * HB, &MK, salts + j * HB, col, Ly.RT, scratch);
  }
  for (size_t i = n - 1; i >= 1; i--) node_hash(tree + i * HB, &MK, tree + 2 * i * HB, tree + (2 * i + 1) * HB);
  double t1 = now();

  /* 4. transcript */
  uint8_t hdr[HDR_BYTES_MAX];
  write_header(hdr, P, &Ly);
  memcpy(hdr + HDR_BYTES - HB, tree + HB, HB);
  transcript_t T;
  tr_init(&T);
  tr_absorb(&T, "stmt", stmt, stmtlen);
  tr_absorb(&T, "label", label, labellen);
  tr_absorb(&T, "header+root", hdr, HDR_BYTES);

  /* 5. tests */
  fe *polI = malloc((size_t)P->sI * K * sizeof(fe));
  fe *polL = malloc((size_t)P->sL * (2 * K - 1) * sizeof(fe));
  fe *polQ = malloc((size_t)P->sQ * (2 * K - 1) * sizeof(fe));
  fe *acc = malloc(n * sizeof(fe)), *tmp = malloc(n * sizeof(fe));
  int internal_err = 0;
  xof_t x;
  for (unsigned s = 0; s < P->sI; s++) {
    tr_xof(&T, "rI", s, &x);
    memcpy(acc, U + (Ly.mI + s) * n, n * sizeof(fe));
    for (size_t r = 0; r < Ly.R; r++) {
      fe c = xof_fe(&x);
      const fe *Ur = U + r * n;
      for (size_t j = 0; j < n; j++) acc[j] = fe_add(acc[j], fe_mul(c, Ur[j]));
    }
    fe_coset_interp(acc, acc, FE_GEN, Ly.logn);
    for (size_t i = K; i < n; i++)
      if (acc[i]) internal_err = 1;
    memcpy(polI + s * K, acc, K * sizeof(fe));
  }
  fe *cvec = malloc(Ly.slots * sizeof(fe));
  for (unsigned s = 0; s < P->sL; s++) {
    tr_xof(&T, "rL", s, &x);
    fe target = linear_combination(cs, &Ly, &x, cvec);
    memcpy(acc, U + (Ly.mL + s) * n, n * sizeof(fe));
    for (size_t r = 0; r < Ly.R; r++) {
      row_poly_on_L(tmp, cvec + r * ell, &Ly, buf);
      const fe *Ur = U + r * n;
      for (size_t j = 0; j < n; j++) acc[j] = fe_add(acc[j], fe_mul(tmp[j], Ur[j]));
    }
    fe_coset_interp(acc, acc, FE_GEN, Ly.logn);
    for (size_t i = 2 * K - 1; i < n; i++)
      if (acc[i]) internal_err = 1;
    memcpy(polL + s * (2 * K - 1), acc, (2 * K - 1) * sizeof(fe));
    fe sumH = fe_mul((fe)K, fe_add(acc[0], acc[K]));
    if (!allow_unsat && sumH != target) internal_err = 1;
  }
  free(cvec);
  for (unsigned s = 0; s < P->sQ; s++) {
    tr_xof(&T, "rQ", s, &x);
    memcpy(acc, U + (Ly.mQ + s) * n, n * sizeof(fe));
    for (size_t rho = 0; rho < Ly.ZR; rho++) {
      fe c = xof_fe(&x);
      const fe *X = U + row_x(&Ly, rho) * n, *Y = U + row_y(&Ly, rho) * n, *Z = U + row_z(&Ly, rho) * n;
      for (size_t j = 0; j < n; j++) acc[j] = fe_add(acc[j], fe_mul(c, fe_sub(fe_mul(X[j], Y[j]), Z[j])));
    }
    fe_coset_interp(acc, acc, FE_GEN, Ly.logn);
    for (size_t i = 2 * K - 1; i < n; i++)
      if (acc[i]) internal_err = 1;
    memcpy(polQ + s * (2 * K - 1), acc, (2 * K - 1) * sizeof(fe));
  }
  if (internal_err && !allow_unsat) {
    fprintf(stderr, "ligero prover: internal consistency check failed\n");
    free(U); free(buf); free(salts); free(tree); free(col); free(scratch);
    free(polI); free(polL); free(polQ); free(acc); free(tmp);
    return -4;
  }
  double t2 = now();

  /* 6. serialize polynomials, absorb, derive column indices */
  size_t total = proof_size(P, &Ly);
  uint8_t *pf = malloc(total), *w = pf;
  memcpy(w, hdr, HDR_BYTES);
  w += HDR_BYTES;
  uint8_t *polys_start = w;
  for (size_t i = 0; i < (size_t)P->sI * K; i++, w += 8) put_fe(w, polI[i]);
  for (size_t i = 0; i < (size_t)P->sL * (2 * K - 1); i++, w += 8) put_fe(w, polL[i]);
  for (size_t i = 0; i < (size_t)P->sQ * (2 * K - 1); i++, w += 8) put_fe(w, polQ[i]);
  tr_absorb(&T, "polys", polys_start, (size_t)(w - polys_start));
  tr_xof(&T, "cols", 0, &x);
  for (unsigned q = 0; q < P->t; q++) {
    size_t j = (size_t)(xof_u64(&x) & (n - 1));
    memcpy(w, salts + j * HB, HB);
    w += HB;
    for (size_t r = 0; r < Ly.RT; r++, w += 8) put_fe(w, U[r * n + j]);
    size_t idx = n + j;
    for (unsigned lvl = 0; lvl < Ly.logn; lvl++) {
      memcpy(w, tree + (idx ^ 1) * HB, HB);
      w += HB;
      idx >>= 1;
    }
  }
  if ((size_t)(w - pf) != total) abort();
  *proof = pf;
  *prooflen = total;
  double t3 = now();
  if (stats) {
    stats->t_commit = t1 - t0;
    stats->t_tests = t2 - t1;
    stats->t_open = t3 - t2;
    stats->t_total = t3 - t0;
    stats->rows = Ly.RT;
    stats->bytes = total;
  }
  free(U); free(buf); free(salts); free(tree); free(col); free(scratch);
  free(polI); free(polL); free(polQ); free(acc); free(tmp);
  return 0;
}

/* ================================== VERIFIER ================================== */
int lg_verify(const cs_t *cs, const lg_params_t *P, const uint8_t *stmt, size_t stmtlen, const uint8_t *label,
              size_t labellen, const uint8_t *proof, size_t prooflen, lg_stats_t *stats) {
  double t0 = now();
  layout_t Ly;
  if (mk_layout(&Ly, cs, P)) return -1;
  const size_t K = Ly.K, n = Ly.n, ell = Ly.ell, RT = Ly.RT, tq = P->t;
  const unsigned HB = hb_of(P);
  const size_t HDR_BYTES = hdr_bytes(HB);
  if (prooflen != proof_size(P, &Ly)) return -2;
  uint8_t hdr[HDR_BYTES_MAX];
  write_header(hdr, P, &Ly);
  if (memcmp(hdr, proof, HDR_BYTES - HB)) return -3; /* parameters / shape mismatch */
  const uint8_t *root = proof + HDR_BYTES - HB;
  const uint8_t *rp = proof + HDR_BYTES;
  int rc = 0;
  mk_ctx_t MK;
  mk_init(&MK, HB);

  /* parse polynomials */
  size_t nI = (size_t)P->sI * K, nL = (size_t)P->sL * (2 * K - 1), nQ = (size_t)P->sQ * (2 * K - 1);
  fe *polI = malloc(nI * sizeof(fe)), *polL = malloc(nL * sizeof(fe)), *polQ = malloc(nQ * sizeof(fe));
  const uint8_t *polys_start = rp;
  for (size_t i = 0; i < nI; i++, rp += 8) if (get_fe(rp, &polI[i])) rc = -4;
  for (size_t i = 0; i < nL; i++, rp += 8) if (get_fe(rp, &polL[i])) rc = -4;
  for (size_t i = 0; i < nQ; i++, rp += 8) if (get_fe(rp, &polQ[i])) rc = -4;
  size_t polys_len = (size_t)(rp - polys_start);

  /* transcript */
  transcript_t T;
  tr_init(&T);
  tr_absorb(&T, "stmt", stmt, stmtlen);
  tr_absorb(&T, "label", label, labellen);
  tr_absorb(&T, "header+root", proof, HDR_BYTES);
  transcript_t T2 = T;
  tr_absorb(&T2, "polys", polys_start, polys_len);
  xof_t x;
  tr_xof(&T2, "cols", 0, &x);
  size_t *J = malloc(tq * sizeof(size_t));
  fe *cols = malloc(tq * RT * sizeof(fe));
  fe *et = malloc(tq * sizeof(fe));
  uint8_t *scratch = malloc(8 * RT);
  for (size_t q = 0; q < tq && rc == 0; q++) {
    J[q] = (size_t)(xof_u64(&x) & (n - 1));
    et[q] = eta(&Ly, J[q]);
    const uint8_t *salt = rp;
    rp += HB;
    for (size_t r = 0; r < RT; r++, rp += 8)
      if (get_fe(rp, &cols[q * RT + r])) rc = -4;
    uint8_t h[HBMAX];
    leaf_hash(h, &MK, salt, cols + q * RT, RT, scratch);
    size_t idx = n + J[q];
    for (unsigned lvl = 0; lvl < Ly.logn; lvl++, rp += HB) {
      if (idx & 1) node_hash(h, &MK, rp, h);
      else node_hash(h, &MK, h, rp);
      idx >>= 1;
    }
    if (memcmp(h, root, HB)) rc = -5;
  }

  /* interleaved test */
  for (unsigned s = 0; s < P->sI && rc == 0; s++) {
    tr_xof(&T, "rI", s, &x);
    fe *rI = malloc(Ly.R * sizeof(fe));
    for (size_t r = 0; r < Ly.R; r++) rI[r] = xof_fe(&x);
    for (size_t q = 0; q < tq; q++) {
      fe rhs = cols[q * RT + Ly.mI + s];
      for (size_t r = 0; r < Ly.R; r++) rhs = fe_add(rhs, fe_mul(rI[r], cols[q * RT + r]));
      if (fe_poly_eval(polI + s * K, K, et[q]) != rhs) rc = -6;
    }
    free(rI);
  }
  /* linear test */
  if (rc == 0) {
    fe *cvec = malloc(Ly.slots * sizeof(fe));
    fe *buf = malloc(K * sizeof(fe)), *tmp = malloc(n * sizeof(fe)), *S = malloc(tq * sizeof(fe));
    for (unsigned s = 0; s < P->sL && rc == 0; s++) {
      const fe *qs = polL + s * (2 * K - 1);
      tr_xof(&T, "rL", s, &x);
      fe target = linear_combination(cs, &Ly, &x, cvec);
      if (fe_mul((fe)K, fe_add(qs[0], qs[K])) != target) { rc = -7; break; }
      for (size_t q = 0; q < tq; q++) S[q] = cols[q * RT + Ly.mL + s];
      for (size_t r = 0; r < Ly.R; r++) {
        row_poly_on_L(tmp, cvec + r * ell, &Ly, buf);
        for (size_t q = 0; q < tq; q++) S[q] = fe_add(S[q], fe_mul(tmp[J[q]], cols[q * RT + r]));
      }
      for (size_t q = 0; q < tq; q++)
        if (fe_poly_eval(qs, 2 * K - 1, et[q]) != S[q]) rc = -8;
    }
    free(cvec); free(buf); free(tmp); free(S);
  }
  /* quadratic test */
  if (rc == 0) {
    fe *f = malloc(K * sizeof(fe));
    for (unsigned s = 0; s < P->sQ && rc == 0; s++) {
      const fe *ps = polQ + s * (2 * K - 1);
      for (size_t i = 0; i < K; i++) f[i] = (i < K - 1) ? fe_add(ps[i], ps[i + K]) : ps[i];
      fe_ntt(f, Ly.logK); /* f(w_K^j) = p_s(w_K^j) */
      for (size_t j = 0; j < ell; j++)
        if (f[j]) { rc = -9; break; }
      if (rc) break;
      tr_xof(&T, "rQ", s, &x);
      fe *rQ = malloc(Ly.ZR * sizeof(fe));
      for (size_t rho = 0; rho < Ly.ZR; rho++) rQ[rho] = xof_fe(&x);
      for (size_t q = 0; q < tq; q++) {
        const fe *c = cols + q * RT;
        fe rhs = c[Ly.mQ + s];
        for (size_t rho = 0; rho < Ly.ZR; rho++)
          rhs = fe_add(rhs, fe_mul(rQ[rho], fe_sub(fe_mul(c[row_x(&Ly, rho)], c[row_y(&Ly, rho)]), c[row_z(&Ly, rho)])));
        if (fe_poly_eval(ps, 2 * K - 1, et[q]) != rhs) rc = -10;
      }
      free(rQ);
    }
    free(f);
  }
  if (stats) {
    stats->t_total = now() - t0;
    stats->rows = RT;
    stats->bytes = prooflen;
  }
  free(polI); free(polL); free(polQ); free(J); free(cols); free(et); free(scratch);
  return rc;
}
