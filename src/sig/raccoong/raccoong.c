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

#define RACCOONG_44_SK_S_OFFSET 0
#define RACCOONG_44_SK_E_OFFSET (RACCOONG_44_SK_S_OFFSET + RACCOONG_44_S_BYTES)
#define RACCOONG_44_SK_PK_OFFSET (RACCOONG_44_SK_E_OFFSET + RACCOONG_44_E_BYTES)
#define RACCOONG_44_SK_PAD_OFFSET (RACCOONG_44_SK_PK_OFFSET + RACCOONG_44_PUBLIC_KEY_BYTES)

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

static void raccoong_poly_add(int32_t *out, const int32_t *a, const int32_t *b) {
for (size_t i = 0; i < RACCOONG_44_N; i++) {
out[i] = raccoong_mod_q((int64_t)a[i] + b[i]);
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

const uint8_t *public_key = secret_key + RACCOONG_44_SK_PK_OFFSET;
raccoong_44_shake256_domain(signature, RACCOONG_44_SIGNATURE_BYTES,
                            "Raccoon-G-44/Sign-FS", public_key, RACCOONG_44_PUBLIC_KEY_BYTES, message, message_len, NULL, 0);
*signature_len = RACCOONG_44_SIGNATURE_BYTES;
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
if (signature == NULL || public_key == NULL || (message == NULL && message_len != 0) || signature_len != RACCOONG_44_SIGNATURE_BYTES) {
return OQS_ERROR;
}

uint8_t *expected = OQS_MEM_malloc(RACCOONG_44_SIGNATURE_BYTES);
if (expected == NULL) {
return OQS_ERROR;
}

raccoong_44_shake256_domain(expected, RACCOONG_44_SIGNATURE_BYTES,
                            "Raccoon-G-44/Sign-FS", public_key, RACCOONG_44_PUBLIC_KEY_BYTES, message, message_len, NULL, 0);
int cmp = OQS_MEM_secure_bcmp(expected, signature, RACCOONG_44_SIGNATURE_BYTES);
OQS_MEM_secure_free(expected, RACCOONG_44_SIGNATURE_BYTES);
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
uint8_t msg[RACCOONG_44_PUBLIC_KEY_BYTES + 4];
uint8_t omega[RACCOONG_44_RERAND_BYTES];
memcpy(msg, pk_parent, RACCOONG_44_PUBLIC_KEY_BYTES);
raccoong_u32_to_be(msg + RACCOONG_44_PUBLIC_KEY_BYTES, index);
raccoong_hmac_sha512(omega, chaincode, RACCOONG_44_CHAINCODE_BYTES, msg, sizeof(msg));
return raccoong_44_hd_randpk(pk_parent, omega, pk_child);
}

OQS_STATUS raccoong_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child) {
if (sk_parent == NULL || chaincode == NULL || sk_child == NULL || pk_child == NULL) {
return OQS_ERROR;
}

uint8_t pk_parent[RACCOONG_44_PUBLIC_KEY_BYTES];
memcpy(pk_parent, sk_parent + RACCOONG_44_SK_PK_OFFSET, RACCOONG_44_PUBLIC_KEY_BYTES);

uint8_t msg[RACCOONG_44_PUBLIC_KEY_BYTES + 4];
uint8_t omega[RACCOONG_44_RERAND_BYTES];
memcpy(msg, pk_parent, RACCOONG_44_PUBLIC_KEY_BYTES);
raccoong_u32_to_be(msg + RACCOONG_44_PUBLIC_KEY_BYTES, index);
raccoong_hmac_sha512(omega, chaincode, RACCOONG_44_CHAINCODE_BYTES, msg, sizeof(msg));

OQS_STATUS rc = raccoong_44_hd_randsk(sk_parent, omega, sk_child, pk_child);
OQS_MEM_cleanse(pk_parent, sizeof(pk_parent));
OQS_MEM_cleanse(omega, sizeof(omega));
return rc;
}
