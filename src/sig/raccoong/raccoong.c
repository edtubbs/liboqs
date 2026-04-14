// SPDX-License-Identifier: MIT

#include <stdint.h>
#include <string.h>

#include <oqs/common.h>
#include <oqs/rand.h>
#include <oqs/sha2.h>
#include <oqs/sha3.h>

#include "raccoong.h"
#include "raccoong_local.h"
#include "raccoong_params.h"

/*
 * Paper reference: ePrint 2026/380, Sec. 4-5 (DetKeyGen, RandPK/RandSK,
 * CKDer_pub/CKDer_priv) and App. B (Raccoon-G-44 parameters).
 */

#define RACCOONG_44_Q 8380417
#define RACCOONG_44_N 256
#define RACCOONG_44_K 4
#define RACCOONG_44_L 4

#define RACCOONG_44_POLY_PACKED_BYTES (RACCOONG_44_N * 3)
#define RACCOONG_44_A_BYTES (RACCOONG_44_K * RACCOONG_44_L * RACCOONG_44_POLY_PACKED_BYTES)
#define RACCOONG_44_T_BYTES (RACCOONG_44_K * RACCOONG_44_POLY_PACKED_BYTES)
#define RACCOONG_44_S_BYTES (RACCOONG_44_L * RACCOONG_44_POLY_PACKED_BYTES)
#define RACCOONG_44_E_BYTES (RACCOONG_44_K * RACCOONG_44_POLY_PACKED_BYTES)

#define RACCOONG_44_PK_A_OFFSET 0
#define RACCOONG_44_PK_T_OFFSET (RACCOONG_44_PK_A_OFFSET + RACCOONG_44_A_BYTES)
#define RACCOONG_44_PK_PAD_OFFSET (RACCOONG_44_PK_T_OFFSET + RACCOONG_44_T_BYTES)
#define RACCOONG_44_PK_PAYLOAD_BYTES RACCOONG_44_PK_PAD_OFFSET

#define RACCOONG_44_SK_S_OFFSET 0
#define RACCOONG_44_SK_E_OFFSET (RACCOONG_44_SK_S_OFFSET + RACCOONG_44_S_BYTES)
#define RACCOONG_44_SK_PK_OFFSET (RACCOONG_44_SK_E_OFFSET + RACCOONG_44_E_BYTES)
#define RACCOONG_44_SK_PAD_OFFSET (RACCOONG_44_SK_PK_OFFSET + RACCOONG_44_PUBLIC_KEY_BYTES)

#define RACCOONG_44_CHAL_HASH_BYTES 32
#define RACCOONG_44_TAU 23
#define RACCOONG_44_NU_T 4
#define RACCOONG_44_NU_W 6
#define RACCOONG_44_Q_T (RACCOONG_44_Q >> RACCOONG_44_NU_T)
#define RACCOONG_44_Q_W (RACCOONG_44_Q >> RACCOONG_44_NU_W)

#define RACCOONG_44_SIG_C_OFFSET 0
#define RACCOONG_44_SIG_Z_OFFSET (RACCOONG_44_SIG_C_OFFSET + RACCOONG_44_CHAL_HASH_BYTES)
#define RACCOONG_44_SIG_Z_BYTES RACCOONG_44_S_BYTES
#define RACCOONG_44_SIG_H_OFFSET (RACCOONG_44_SIG_Z_OFFSET + RACCOONG_44_SIG_Z_BYTES)
#define RACCOONG_44_SIG_H_BYTES RACCOONG_44_E_BYTES
#define RACCOONG_44_SIG_PAYLOAD_BYTES (RACCOONG_44_SIG_H_OFFSET + RACCOONG_44_SIG_H_BYTES)
#define RACCOONG_44_SIG_INTEGRITY_BYTES 32
#define RACCOONG_44_SIG_INTEGRITY_OFFSET RACCOONG_44_SIG_PAYLOAD_BYTES

/* Approximate CDT for sigma=3.2 (Sec. 5.2/App. C); thresholds over [0, 65535]. */
static const uint16_t raccoong_sigma32_cdt[] = {
8169, 23731, 37172, 47702, 55183, 60004, 62822, 64315, 65033, 65346,
65470, 65514, 65529, 65533, 65534, 65534, 65534, 65534, 65534, 65534,
65534, 65534, 65534, 65534, 65534, 65534, 65534, 65535, 65535, 65535,
65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
65535
};

static void raccoong_44_shake256_domain(uint8_t *out, size_t out_len,
                                        const char *domain,
                                        const uint8_t *in0, size_t in0_len,
                                        const uint8_t *in1, size_t in1_len,
                                        const uint8_t *in2, size_t in2_len) {
OQS_SHA3_shake256_inc_ctx state;
OQS_SHA3_shake256_inc_init(&state);
OQS_SHA3_shake256_inc_absorb(&state, (const uint8_t *)domain, strlen(domain));
if (in0 != NULL && in0_len > 0) {
OQS_SHA3_shake256_inc_absorb(&state, in0, in0_len);
}
if (in1 != NULL && in1_len > 0) {
OQS_SHA3_shake256_inc_absorb(&state, in1, in1_len);
}
if (in2 != NULL && in2_len > 0) {
OQS_SHA3_shake256_inc_absorb(&state, in2, in2_len);
}
OQS_SHA3_shake256_inc_finalize(&state);
OQS_SHA3_shake256_inc_squeeze(out, out_len, &state);
OQS_SHA3_shake256_inc_ctx_release(&state);
}

void raccoong_u32_to_be(uint8_t out[4], uint32_t value) {
out[0] = (uint8_t)(value >> 24);
out[1] = (uint8_t)(value >> 16);
out[2] = (uint8_t)(value >> 8);
out[3] = (uint8_t)value;
}

static int32_t raccoong_mod_q(int64_t x) {
int64_t r = x % RACCOONG_44_Q;
if (r < 0) {
r += RACCOONG_44_Q;
}
return (int32_t)r;
}

static void raccoong_pack_poly3(uint8_t *out, const int32_t *poly) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
uint32_t v = (uint32_t)raccoong_mod_q(poly[i]);
out[3 * i + 0] = (uint8_t)(v & 0xFFu);
out[3 * i + 1] = (uint8_t)((v >> 8) & 0xFFu);
out[3 * i + 2] = (uint8_t)((v >> 16) & 0x7Fu);
}
}

static void raccoong_unpack_poly3(int32_t *poly, const uint8_t *in) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
uint32_t v = (uint32_t)in[3 * i + 0]
             | ((uint32_t)in[3 * i + 1] << 8)
             | ((uint32_t)(in[3 * i + 2] & 0x7Fu) << 16);
poly[i] = (int32_t)(v % RACCOONG_44_Q);
}
}

static uint32_t raccoong_unpack_poly3_raw_coeff(const uint8_t *in, size_t i) {
return (uint32_t)in[3 * i + 0]
       | ((uint32_t)in[3 * i + 1] << 8)
       | ((uint32_t)(in[3 * i + 2] & 0x7Fu) << 16);
}

static void raccoong_poly_add(int32_t *out, const int32_t *a, const int32_t *b) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
out[i] = raccoong_mod_q((int64_t)a[i] + b[i]);
}
}

static void raccoong_poly_sub_mod(int32_t *out, const int32_t *a, const int32_t *b, int32_t mod) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
int64_t d = (int64_t)a[i] - b[i];
int32_t r = (int32_t)(d % mod);
if (r < 0) {
r += mod;
}
out[i] = r;
}
}

static void raccoong_poly_add_mod(int32_t *out, const int32_t *a, const int32_t *b, int32_t mod) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
int64_t d = (int64_t)a[i] + b[i];
int32_t r = (int32_t)(d % mod);
if (r < 0) {
r += mod;
}
out[i] = r;
}
}

static void raccoong_poly_lshift_mod(int32_t *out, const int32_t *a, uint32_t shift, int32_t mod) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
out[i] = (int32_t)(((int64_t)a[i] << shift) % mod);
}
}

static void raccoong_poly_rshift_round_mod(int32_t *out, const int32_t *a, uint32_t shift, int32_t mod) {
const int32_t mid = (int32_t)(1u << (shift - 1));
for (size_t i = 0; i < RACCOONG_44_N; i++) {
int32_t x = a[i] % mod;
if (x < 0) {
x += mod;
}
out[i] = ((x + mid) >> shift) % mod;
}
}

/* Multiplication in Z_q[x]/(x^N+1). */
static void raccoong_poly_mul(int32_t *out, const int32_t *a, const int32_t *b) {
int64_t acc[RACCOONG_44_N] = {0};
for (size_t i = 0; i < RACCOONG_44_N; i++) {
for (size_t j = 0; j < RACCOONG_44_N; j++) {
size_t d = i + j;
int64_t t = (int64_t)a[i] * b[j];
if (d >= RACCOONG_44_N) {
d -= RACCOONG_44_N;
acc[d] -= t;
} else {
acc[d] += t;
}
}
}
for (size_t i = 0; i < RACCOONG_44_N; i++) {
out[i] = raccoong_mod_q(acc[i]);
}
}

static void raccoong_expand_a(int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N], const uint8_t rho[32]) {
uint8_t seed[34];
memcpy(seed, rho, 32);
for (size_t i = 0; i < RACCOONG_44_K; i++) {
for (size_t j = 0; j < RACCOONG_44_L; j++) {
seed[32] = (uint8_t)i;
seed[33] = (uint8_t)j;
uint8_t buf[4 * RACCOONG_44_N];
raccoong_44_shake256_domain(buf, sizeof(buf), "Raccoon-G-44/ExpandA", seed, sizeof(seed), NULL, 0, NULL, 0);
for (size_t n = 0; n < RACCOONG_44_N; n++) {
uint32_t x = (uint32_t)buf[4 * n + 0]
             | ((uint32_t)buf[4 * n + 1] << 8)
             | ((uint32_t)buf[4 * n + 2] << 16)
             | ((uint32_t)buf[4 * n + 3] << 24);
A[i][j][n] = (int32_t)(x % RACCOONG_44_Q);
}
}
}
}

static int32_t raccoong_sample_gaussian_coeff(uint16_t u16, uint8_t signbit) {
size_t mag = 0;
for (size_t i = 0; i < sizeof(raccoong_sigma32_cdt) / sizeof(raccoong_sigma32_cdt[0]); i++) {
/* Branch-free count of thresholds less than u16. */
mag += (size_t)(u16 > raccoong_sigma32_cdt[i]);
}
if (mag == 0) {
return 0;
}
int32_t v = (int32_t)mag;
if (signbit & 1u) {
v = -v;
}
return v;
}

static void raccoong_sample_gaussian_vec(int32_t *vec, size_t polys, const uint8_t *seed, size_t seed_len, const char *domain) {
uint8_t buf[3 * RACCOONG_44_N * RACCOONG_44_K];
const size_t needed = 3 * RACCOONG_44_N * polys;
raccoong_44_shake256_domain(buf, needed, domain, seed, seed_len, NULL, 0, NULL, 0);
for (size_t p = 0; p < polys; p++) {
for (size_t n = 0; n < RACCOONG_44_N; n++) {
size_t off = 3 * (p * RACCOONG_44_N + n);
uint16_t u16 = (uint16_t)buf[off] | ((uint16_t)buf[off + 1] << 8);
uint8_t sign = buf[off + 2] & 1u;
vec[p * RACCOONG_44_N + n] = raccoong_sample_gaussian_coeff(u16, sign);
}
}
}

static void raccoong_hmac_sha512(uint8_t out[64], const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len) {
uint8_t k0[128] = {0};
if (key_len > sizeof(k0)) {
OQS_SHA2_sha512(k0, key, key_len);
} else {
memcpy(k0, key, key_len);
}

uint8_t ipad[128], opad[128];
for (size_t i = 0; i < sizeof(k0); i++) {
ipad[i] = (uint8_t)(k0[i] ^ 0x36u);
opad[i] = (uint8_t)(k0[i] ^ 0x5cu);
}

uint8_t inner_input[128 + 4 + RACCOONG_44_PUBLIC_KEY_BYTES];
uint8_t inner_hash[64];
memcpy(inner_input, ipad, 128);
if (msg_len > 0) {
memcpy(inner_input + 128, msg, msg_len);
}
OQS_SHA2_sha512(inner_hash, inner_input, 128 + msg_len);

uint8_t outer_input[128 + 64];
memcpy(outer_input, opad, 128);
memcpy(outer_input + 128, inner_hash, 64);
OQS_SHA2_sha512(out, outer_input, sizeof(outer_input));

OQS_MEM_cleanse(k0, sizeof(k0));
OQS_MEM_cleanse(ipad, sizeof(ipad));
OQS_MEM_cleanse(opad, sizeof(opad));
OQS_MEM_cleanse(inner_hash, sizeof(inner_hash));
}

static void raccoong_serialize_pk(uint8_t *public_key,
                                  int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N],
                                  int32_t t[RACCOONG_44_K][RACCOONG_44_N]) {
size_t off = RACCOONG_44_PK_A_OFFSET;
for (size_t i = 0; i < RACCOONG_44_K; i++) {
for (size_t j = 0; j < RACCOONG_44_L; j++) {
raccoong_pack_poly3(public_key + off, A[i][j]);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
}
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_pack_poly3(public_key + off, t[i]);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
if (RACCOONG_44_PUBLIC_KEY_BYTES > off) {
memset(public_key + off, 0, RACCOONG_44_PUBLIC_KEY_BYTES - off);
}
}

static OQS_STATUS raccoong_deserialize_pk(int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N],
                                          int32_t t[RACCOONG_44_K][RACCOONG_44_N],
                                          const uint8_t *public_key) {
if (public_key == NULL) {
return OQS_ERROR;
}
size_t off = RACCOONG_44_PK_A_OFFSET;
for (size_t i = 0; i < RACCOONG_44_K; i++) {
for (size_t j = 0; j < RACCOONG_44_L; j++) {
raccoong_unpack_poly3(A[i][j], public_key + off);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
}
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_unpack_poly3(t[i], public_key + off);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
return OQS_SUCCESS;
}

static void raccoong_serialize_sk(uint8_t *secret_key,
                                  int32_t s[RACCOONG_44_L][RACCOONG_44_N],
                                  int32_t e[RACCOONG_44_K][RACCOONG_44_N],
                                  const uint8_t *public_key) {
size_t off = RACCOONG_44_SK_S_OFFSET;
for (size_t i = 0; i < RACCOONG_44_L; i++) {
raccoong_pack_poly3(secret_key + off, s[i]);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_pack_poly3(secret_key + off, e[i]);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
memcpy(secret_key + RACCOONG_44_SK_PK_OFFSET, public_key, RACCOONG_44_PUBLIC_KEY_BYTES);
if (RACCOONG_44_SECRET_KEY_BYTES > RACCOONG_44_SK_PAD_OFFSET) {
memset(secret_key + RACCOONG_44_SK_PAD_OFFSET, 0, RACCOONG_44_SECRET_KEY_BYTES - RACCOONG_44_SK_PAD_OFFSET);
}
}

static OQS_STATUS raccoong_deserialize_sk(int32_t s[RACCOONG_44_L][RACCOONG_44_N],
                                          int32_t e[RACCOONG_44_K][RACCOONG_44_N],
                                          uint8_t *pk,
                                          const uint8_t *secret_key) {
if (secret_key == NULL) {
return OQS_ERROR;
}
size_t off = RACCOONG_44_SK_S_OFFSET;
for (size_t i = 0; i < RACCOONG_44_L; i++) {
raccoong_unpack_poly3(s[i], secret_key + off);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_unpack_poly3(e[i], secret_key + off);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
if (pk != NULL) {
memcpy(pk, secret_key + RACCOONG_44_SK_PK_OFFSET, RACCOONG_44_PUBLIC_KEY_BYTES);
}
return OQS_SUCCESS;
}

static void raccoong_compute_t(int32_t t[RACCOONG_44_K][RACCOONG_44_N],
                               int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N],
                               int32_t s[RACCOONG_44_L][RACCOONG_44_N],
                               int32_t e[RACCOONG_44_K][RACCOONG_44_N]) {
for (size_t i = 0; i < RACCOONG_44_K; i++) {
int32_t sum[RACCOONG_44_N] = {0};
for (size_t j = 0; j < RACCOONG_44_L; j++) {
int32_t prod[RACCOONG_44_N];
raccoong_poly_mul(prod, A[i][j], s[j]);
raccoong_poly_add(sum, sum, prod);
}
raccoong_poly_add(t[i], sum, e[i]);
}
}

static void raccoong_chal_poly(int32_t c[RACCOONG_44_N], const uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES]) {
memset(c, 0, RACCOONG_44_N * sizeof(int32_t));
uint8_t seed[RACCOONG_44_CHAL_HASH_BYTES + 1];
memcpy(seed, c_hash, RACCOONG_44_CHAL_HASH_BYTES);
seed[RACCOONG_44_CHAL_HASH_BYTES] = (uint8_t)RACCOONG_44_TAU;
uint8_t buf[2 * RACCOONG_44_TAU * 4];
raccoong_44_shake256_domain(buf, sizeof(buf), "Raccoon-G-44/ChalPoly", seed, sizeof(seed), NULL, 0, NULL, 0);
size_t wt = 0;
size_t off = 0;
while (wt < RACCOONG_44_TAU) {
if (off + 2 > sizeof(buf)) {
raccoong_44_shake256_domain(buf, sizeof(buf), "Raccoon-G-44/ChalPoly/extend", c_hash, RACCOONG_44_CHAL_HASH_BYTES, (const uint8_t *)&wt, sizeof(wt), NULL, 0);
off = 0;
}
uint16_t x = (uint16_t)buf[off] | ((uint16_t)buf[off + 1] << 8);
off += 2;
size_t idx = (size_t)((x >> 1) & (RACCOONG_44_N - 1));
int32_t sign = (x & 1u) ? 1 : -1;
if (c[idx] == 0) {
c[idx] = sign;
wt++;
}
}
}

static void raccoong_compute_mu(uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES],
                                const uint8_t *public_key_payload,
                                const uint8_t *message, size_t message_len) {
uint8_t tr[RACCOONG_44_CHAL_HASH_BYTES];
OQS_SHA3_shake256(tr, sizeof(tr), public_key_payload, RACCOONG_44_PK_PAYLOAD_BYTES);
OQS_SHA3_shake256_inc_ctx st;
OQS_SHA3_shake256_inc_init(&st);
OQS_SHA3_shake256_inc_absorb(&st, tr, sizeof(tr));
if (message_len > 0) {
OQS_SHA3_shake256_inc_absorb(&st, message, message_len);
}
OQS_SHA3_shake256_inc_finalize(&st);
OQS_SHA3_shake256_inc_squeeze(mu, RACCOONG_44_CHAL_HASH_BYTES, &st);
OQS_SHA3_shake256_inc_ctx_release(&st);
OQS_MEM_cleanse(tr, sizeof(tr));
}

static void raccoong_hash_vec(uint8_t out[RACCOONG_44_CHAL_HASH_BYTES],
                              const uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES],
                              int32_t v[RACCOONG_44_K][RACCOONG_44_N],
                              int32_t mod) {
uint8_t packed[RACCOONG_44_E_BYTES];
size_t off = 0;
for (size_t i = 0; i < RACCOONG_44_K; i++) {
for (size_t n = 0; n < RACCOONG_44_N; n++) {
uint32_t x = (uint32_t)(v[i][n] % mod);
if ((int32_t)x < 0) {
x += (uint32_t)mod;
}
packed[off++] = (uint8_t)(x & 0xFFu);
packed[off++] = (uint8_t)((x >> 8) & 0xFFu);
packed[off++] = (uint8_t)((x >> 16) & 0x7Fu);
}
}
raccoong_44_shake256_domain(out, RACCOONG_44_CHAL_HASH_BYTES,
                            "Raccoon-G-44/HashVec", mu, RACCOONG_44_CHAL_HASH_BYTES, packed, sizeof(packed), NULL, 0);
OQS_MEM_cleanse(packed, sizeof(packed));
}

static void raccoong_signature_integrity_tag(uint8_t out[RACCOONG_44_SIG_INTEGRITY_BYTES],
                                             const uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES],
                                             const uint8_t *sig_payload, size_t sig_payload_len) {
raccoong_44_shake256_domain(out, RACCOONG_44_SIG_INTEGRITY_BYTES,
                            "Raccoon-G-44/SignatureIntegrity",
                            mu, RACCOONG_44_CHAL_HASH_BYTES,
                            sig_payload, sig_payload_len,
                            NULL, 0);
}

static void raccoong_serialize_sig(uint8_t *signature,
                                   const uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES],
                                   int32_t z[RACCOONG_44_L][RACCOONG_44_N],
                                   int32_t h[RACCOONG_44_K][RACCOONG_44_N]) {
memcpy(signature + RACCOONG_44_SIG_C_OFFSET, c_hash, RACCOONG_44_CHAL_HASH_BYTES);
size_t off = RACCOONG_44_SIG_Z_OFFSET;
for (size_t i = 0; i < RACCOONG_44_L; i++) {
raccoong_pack_poly3(signature + off, z[i]);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
off = RACCOONG_44_SIG_H_OFFSET;
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_pack_poly3(signature + off, h[i]);
off += RACCOONG_44_POLY_PACKED_BYTES;
}
if (RACCOONG_44_SIGNATURE_BYTES > RACCOONG_44_SIG_PAYLOAD_BYTES) {
memset(signature + RACCOONG_44_SIG_PAYLOAD_BYTES, 0, RACCOONG_44_SIGNATURE_BYTES - RACCOONG_44_SIG_PAYLOAD_BYTES);
}
}

static OQS_STATUS raccoong_deserialize_sig(uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES],
                                           int32_t z[RACCOONG_44_L][RACCOONG_44_N],
                                           int32_t h[RACCOONG_44_K][RACCOONG_44_N],
                                           const uint8_t *signature) {
if (signature == NULL) {
return OQS_ERROR;
}
memcpy(c_hash, signature + RACCOONG_44_SIG_C_OFFSET, RACCOONG_44_CHAL_HASH_BYTES);
size_t off = RACCOONG_44_SIG_Z_OFFSET;
for (size_t i = 0; i < RACCOONG_44_L; i++) {
for (size_t n = 0; n < RACCOONG_44_N; n++) {
uint32_t v = raccoong_unpack_poly3_raw_coeff(signature + off, n);
if (v >= RACCOONG_44_Q) {
return OQS_ERROR;
}
z[i][n] = (int32_t)v;
}
off += RACCOONG_44_POLY_PACKED_BYTES;
}
off = RACCOONG_44_SIG_H_OFFSET;
for (size_t i = 0; i < RACCOONG_44_K; i++) {
for (size_t n = 0; n < RACCOONG_44_N; n++) {
uint32_t v = raccoong_unpack_poly3_raw_coeff(signature + off, n);
if (v >= RACCOONG_44_Q_W) {
return OQS_ERROR;
}
h[i][n] = (int32_t)v;
}
off += RACCOONG_44_POLY_PACKED_BYTES;
}
for (size_t i = RACCOONG_44_SIG_INTEGRITY_OFFSET + RACCOONG_44_SIG_INTEGRITY_BYTES; i < RACCOONG_44_SIGNATURE_BYTES; i++) {
if (signature[i] != 0) {
return OQS_ERROR;
}
}
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_keypair_det(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed, size_t seed_len) {
if (public_key == NULL || secret_key == NULL || seed == NULL || (seed_len != 32 && seed_len != RACCOONG_44_SEED_BYTES)) {
return OQS_ERROR;
}

uint8_t rho[32];
raccoong_44_shake256_domain(rho, sizeof(rho), "Raccoon-G-44/DetKeyGen/rho", seed, seed_len, NULL, 0, NULL, 0);

int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N];
int32_t s_flat[RACCOONG_44_L * RACCOONG_44_N];
int32_t e_flat[RACCOONG_44_K * RACCOONG_44_N];
int32_t (*s)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])s_flat;
int32_t (*e)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])e_flat;
int32_t t[RACCOONG_44_K][RACCOONG_44_N];

raccoong_expand_a(A, rho);
raccoong_sample_gaussian_vec(s_flat, RACCOONG_44_L, seed, seed_len, "Raccoon-G-44/DetKeyGen/s");
raccoong_sample_gaussian_vec(e_flat, RACCOONG_44_K, seed, seed_len, "Raccoon-G-44/DetKeyGen/e");
raccoong_compute_t(t, A, s, e);

raccoong_serialize_pk(public_key, A, t);
raccoong_serialize_sk(secret_key, s, e, public_key);

OQS_MEM_cleanse(rho, sizeof(rho));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
uint8_t seed[RACCOONG_44_SEED_BYTES];
OQS_randombytes(seed, sizeof(seed));
OQS_STATUS rc = raccoong_44_keypair_det(public_key, secret_key, seed, sizeof(seed));
OQS_MEM_cleanse(seed, sizeof(seed));
return rc;
}

OQS_STATUS raccoong_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
if (signature == NULL || signature_len == NULL || secret_key == NULL || (message == NULL && message_len != 0)) {
return OQS_ERROR;
}

int32_t s[RACCOONG_44_L][RACCOONG_44_N];
int32_t e[RACCOONG_44_K][RACCOONG_44_N];
uint8_t public_key[RACCOONG_44_PUBLIC_KEY_BYTES];
if (raccoong_deserialize_sk(s, e, public_key, secret_key) != OQS_SUCCESS) {
return OQS_ERROR;
}

int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N];
int32_t t[RACCOONG_44_K][RACCOONG_44_N];
if (raccoong_deserialize_pk(A, t, public_key) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t nonce_seed[32];
OQS_randombytes(nonce_seed, sizeof(nonce_seed));
int32_t r_flat[RACCOONG_44_L * RACCOONG_44_N];
int32_t e2_flat[RACCOONG_44_K * RACCOONG_44_N];
int32_t (*r)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])r_flat;
int32_t (*e2)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])e2_flat;
raccoong_sample_gaussian_vec(r_flat, RACCOONG_44_L, nonce_seed, sizeof(nonce_seed), "Raccoon-G-44/Sign/r");
raccoong_sample_gaussian_vec(e2_flat, RACCOONG_44_K, nonce_seed, sizeof(nonce_seed), "Raccoon-G-44/Sign/e2");

int32_t w[RACCOONG_44_K][RACCOONG_44_N];
int32_t w_r[RACCOONG_44_K][RACCOONG_44_N];
raccoong_compute_t(w, A, r, e2);
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_poly_rshift_round_mod(w_r[i], w[i], RACCOONG_44_NU_W, RACCOONG_44_Q_W);
}

uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES];
uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES];
raccoong_compute_mu(mu, public_key, message, message_len);
raccoong_hash_vec(c_hash, mu, w_r, RACCOONG_44_Q_W);

int32_t c[RACCOONG_44_N];
raccoong_chal_poly(c, c_hash);

int32_t z[RACCOONG_44_L][RACCOONG_44_N];
for (size_t j = 0; j < RACCOONG_44_L; j++) {
int32_t cs[RACCOONG_44_N];
raccoong_poly_mul(cs, c, s[j]);
raccoong_poly_add(z[j], cs, r[j]);
}

int32_t t_round[RACCOONG_44_K][RACCOONG_44_N];
int32_t t_lift[RACCOONG_44_K][RACCOONG_44_N];
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_poly_rshift_round_mod(t_round[i], t[i], RACCOONG_44_NU_T, RACCOONG_44_Q_T);
raccoong_poly_lshift_mod(t_lift[i], t_round[i], RACCOONG_44_NU_T, RACCOONG_44_Q);
}

int32_t az[RACCOONG_44_K][RACCOONG_44_N];
int32_t zero_e[RACCOONG_44_K][RACCOONG_44_N] = {{0}};
raccoong_compute_t(az, A, z, zero_e);
for (size_t i = 0; i < RACCOONG_44_K; i++) {
int32_t ct[RACCOONG_44_N];
int32_t y[RACCOONG_44_N];
int32_t y_r[RACCOONG_44_N];
raccoong_poly_mul(ct, c, t_lift[i]);
raccoong_poly_sub_mod(y, az[i], ct, RACCOONG_44_Q);
raccoong_poly_rshift_round_mod(y_r, y, RACCOONG_44_NU_W, RACCOONG_44_Q_W);
raccoong_poly_sub_mod(w_r[i], w_r[i], y_r, RACCOONG_44_Q_W);
}

raccoong_serialize_sig(signature, c_hash, z, w_r);
uint8_t tag[RACCOONG_44_SIG_INTEGRITY_BYTES];
raccoong_signature_integrity_tag(tag, mu, signature, RACCOONG_44_SIG_PAYLOAD_BYTES);
memcpy(signature + RACCOONG_44_SIG_INTEGRITY_OFFSET, tag, sizeof(tag));
if (RACCOONG_44_SIGNATURE_BYTES > RACCOONG_44_SIG_INTEGRITY_OFFSET + sizeof(tag)) {
memset(signature + RACCOONG_44_SIG_INTEGRITY_OFFSET + sizeof(tag), 0,
       RACCOONG_44_SIGNATURE_BYTES - RACCOONG_44_SIG_INTEGRITY_OFFSET - sizeof(tag));
}
*signature_len = RACCOONG_44_SIGNATURE_BYTES;
OQS_MEM_cleanse(nonce_seed, sizeof(nonce_seed));
OQS_MEM_cleanse(mu, sizeof(mu));
OQS_MEM_cleanse(c_hash, sizeof(c_hash));
OQS_MEM_cleanse(tag, sizeof(tag));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
if (signature == NULL || public_key == NULL || (message == NULL && message_len != 0) || signature_len != RACCOONG_44_SIGNATURE_BYTES) {
return OQS_ERROR;
}

int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N];
int32_t t[RACCOONG_44_K][RACCOONG_44_N];
if (raccoong_deserialize_pk(A, t, public_key) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES];
int32_t z[RACCOONG_44_L][RACCOONG_44_N];
int32_t h[RACCOONG_44_K][RACCOONG_44_N];
if (raccoong_deserialize_sig(c_hash, z, h, signature) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES];
raccoong_compute_mu(mu, public_key, message, message_len);
int32_t c[RACCOONG_44_N];
raccoong_chal_poly(c, c_hash);

int32_t t_round[RACCOONG_44_K][RACCOONG_44_N];
int32_t t_lift[RACCOONG_44_K][RACCOONG_44_N];
for (size_t i = 0; i < RACCOONG_44_K; i++) {
raccoong_poly_rshift_round_mod(t_round[i], t[i], RACCOONG_44_NU_T, RACCOONG_44_Q_T);
raccoong_poly_lshift_mod(t_lift[i], t_round[i], RACCOONG_44_NU_T, RACCOONG_44_Q);
}

int32_t zero_e[RACCOONG_44_K][RACCOONG_44_N] = {{0}};
int32_t az[RACCOONG_44_K][RACCOONG_44_N];
int32_t w_r[RACCOONG_44_K][RACCOONG_44_N];
raccoong_compute_t(az, A, z, zero_e);
for (size_t i = 0; i < RACCOONG_44_K; i++) {
int32_t ct[RACCOONG_44_N];
int32_t y[RACCOONG_44_N];
raccoong_poly_mul(ct, c, t_lift[i]);
raccoong_poly_sub_mod(y, az[i], ct, RACCOONG_44_Q);
raccoong_poly_rshift_round_mod(w_r[i], y, RACCOONG_44_NU_W, RACCOONG_44_Q_W);
raccoong_poly_add_mod(w_r[i], w_r[i], h[i], RACCOONG_44_Q_W);
}

uint8_t c_hash2[RACCOONG_44_CHAL_HASH_BYTES];
raccoong_hash_vec(c_hash2, mu, w_r, RACCOONG_44_Q_W);
uint8_t tag_expected[RACCOONG_44_SIG_INTEGRITY_BYTES];
raccoong_signature_integrity_tag(tag_expected, mu, signature, RACCOONG_44_SIG_PAYLOAD_BYTES);
int cmp = OQS_MEM_secure_bcmp(c_hash, c_hash2, RACCOONG_44_CHAL_HASH_BYTES);
cmp |= OQS_MEM_secure_bcmp(signature + RACCOONG_44_SIG_INTEGRITY_OFFSET, tag_expected, RACCOONG_44_SIG_INTEGRITY_BYTES);
OQS_MEM_cleanse(mu, sizeof(mu));
OQS_MEM_cleanse(c_hash2, sizeof(c_hash2));
OQS_MEM_cleanse(tag_expected, sizeof(tag_expected));
return (cmp == 0) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_STATUS raccoong_44_hd_randpk(const uint8_t *pk_in, const uint8_t *randomness, uint8_t *pk_out) {
if (pk_in == NULL || randomness == NULL || pk_out == NULL) {
return OQS_ERROR;
}

int32_t A[RACCOONG_44_K][RACCOONG_44_L][RACCOONG_44_N];
int32_t t[RACCOONG_44_K][RACCOONG_44_N];
if (raccoong_deserialize_pk(A, t, pk_in) != OQS_SUCCESS) {
return OQS_ERROR;
}

int32_t sp_flat[RACCOONG_44_L * RACCOONG_44_N];
int32_t ep_flat[RACCOONG_44_K * RACCOONG_44_N];
int32_t (*sp)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])sp_flat;
int32_t (*ep)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])ep_flat;
int32_t delta[RACCOONG_44_K][RACCOONG_44_N];

raccoong_sample_gaussian_vec(sp_flat, RACCOONG_44_L, randomness, RACCOONG_44_RERAND_BYTES, "Raccoon-G-44/RandPK/s_prime");
raccoong_sample_gaussian_vec(ep_flat, RACCOONG_44_K, randomness, RACCOONG_44_RERAND_BYTES, "Raccoon-G-44/RandPK/e_prime");
raccoong_compute_t(delta, A, sp, ep);

for (size_t i = 0; i < RACCOONG_44_K; i++) {
for (size_t n = 0; n < RACCOONG_44_N; n++) {
t[i][n] = raccoong_mod_q((int64_t)t[i][n] + delta[i][n]);
}
}

raccoong_serialize_pk(pk_out, A, t);
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_randsk(const uint8_t *sk_in, const uint8_t *randomness, uint8_t *sk_out, uint8_t *pk_out) {
if (sk_in == NULL || randomness == NULL || sk_out == NULL || pk_out == NULL) {
return OQS_ERROR;
}

int32_t s[RACCOONG_44_L][RACCOONG_44_N];
int32_t e[RACCOONG_44_K][RACCOONG_44_N];
uint8_t pk_parent[RACCOONG_44_PUBLIC_KEY_BYTES];
if (raccoong_deserialize_sk(s, e, pk_parent, sk_in) != OQS_SUCCESS) {
return OQS_ERROR;
}
if (raccoong_44_hd_randpk(pk_parent, randomness, pk_out) != OQS_SUCCESS) {
return OQS_ERROR;
}

int32_t sp_flat[RACCOONG_44_L * RACCOONG_44_N];
int32_t (*sp)[RACCOONG_44_N] = (int32_t (*)[RACCOONG_44_N])sp_flat;
raccoong_sample_gaussian_vec(sp_flat, RACCOONG_44_L, randomness, RACCOONG_44_RERAND_BYTES, "Raccoon-G-44/RandSK/s_prime");

for (size_t i = 0; i < RACCOONG_44_L; i++) {
for (size_t n = 0; n < RACCOONG_44_N; n++) {
s[i][n] = raccoong_mod_q((int64_t)s[i][n] + sp[i][n]);
}
}

raccoong_serialize_sk(sk_out, s, e, pk_out);
OQS_MEM_cleanse(pk_parent, sizeof(pk_parent));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_derive_pub(const uint8_t *pk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *pk_child) {
if (pk_parent == NULL || chaincode == NULL || pk_child == NULL) {
return OQS_ERROR;
}
uint8_t msg[RACCOONG_44_PK_PAYLOAD_BYTES + 4];
uint8_t omega[RACCOONG_44_RERAND_BYTES];
memcpy(msg, pk_parent, RACCOONG_44_PK_PAYLOAD_BYTES);
raccoong_u32_to_be(msg + RACCOONG_44_PK_PAYLOAD_BYTES, index);
raccoong_hmac_sha512(omega, chaincode, RACCOONG_44_CHAINCODE_BYTES, msg, sizeof(msg));
return raccoong_44_hd_randpk(pk_parent, omega, pk_child);
}

OQS_STATUS raccoong_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child) {
if (sk_parent == NULL || chaincode == NULL || sk_child == NULL || pk_child == NULL) {
return OQS_ERROR;
}

uint8_t pk_parent[RACCOONG_44_PUBLIC_KEY_BYTES];
memcpy(pk_parent, sk_parent + RACCOONG_44_SK_PK_OFFSET, RACCOONG_44_PUBLIC_KEY_BYTES);

uint8_t msg[RACCOONG_44_PK_PAYLOAD_BYTES + 4];
uint8_t omega[RACCOONG_44_RERAND_BYTES];
memcpy(msg, pk_parent, RACCOONG_44_PK_PAYLOAD_BYTES);
raccoong_u32_to_be(msg + RACCOONG_44_PK_PAYLOAD_BYTES, index);
raccoong_hmac_sha512(omega, chaincode, RACCOONG_44_CHAINCODE_BYTES, msg, sizeof(msg));

OQS_STATUS rc = raccoong_44_hd_randsk(sk_parent, omega, sk_child, pk_child);
OQS_MEM_cleanse(pk_parent, sizeof(pk_parent));
OQS_MEM_cleanse(omega, sizeof(omega));
return rc;
}
