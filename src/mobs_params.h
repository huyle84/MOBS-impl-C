/*
 * mobs_params.h -- parameters of MOBS[ML-DSA] (see MOBS-main-06-11-2026-v2.tex, Sect. 6).
 *
 * The ML-DSA parameter set is selected at compile time by DILITHIUM_MODE
 * (2 = ML-DSA-44, 3 = ML-DSA-65, 5 = ML-DSA-87), as in the reference code.
 */
#ifndef MOBS_PARAMS_H
#define MOBS_PARAMS_H

#include "params.h" /* ML-DSA reference parameters: K, L, N, Q, D, TAU, ... */

#define MOBS_ATTR_BYTES 32              /* each attribute is a 32-byte string */
#define MOBS_CBYTES CTILDEBYTES         /* commitment length l_c/8 = 32/48/64 */
#define MOBS_RBYTES CTILDEBYTES         /* commitment randomness length */
#define MOBS_DS_BYTES 16
#define MOBS_MAX_ATTRS 256

/* SampleInBall_B: number of SHAKE256 blocks the circuit allows (Lemma 6) */
#if DILITHIUM_MODE == 5
#define MOBS_SIB_BLOCKS 2
#else
#define MOBS_SIB_BLOCKS 1
#endif

extern const uint8_t MOBS_DS_COM[MOBS_DS_BYTES]; /* "MOBS-v1/commit\0\0" */
extern const uint8_t MOBS_DS_ISS[MOBS_DS_BYTES]; /* "MOBS-v1/issue\0\0\0" */
extern const uint8_t MOBS_CTX_ML[MOBS_DS_BYTES]; /* FIPS 204 context string */

#endif
