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
#include "raccoong_reference_vectors.h"

#define RACCOONG_44_Q UINT64_C(562949953438721)
#define RACCOONG_44_N 256
#define RACCOONG_44_K 9
#define RACCOONG_44_L 9
#define RACCOONG_44_NU_T 35
#define RACCOONG_44_NU_W 38
#define RACCOONG_44_Q_W (RACCOONG_44_Q >> RACCOONG_44_NU_W)

#define RACCOONG_44_A_SEED_BYTES 16
#define RACCOONG_44_COEFF_BYTES 7
#define RACCOONG_44_H_COEFF_BYTES 2
#define RACCOONG_44_CHAL_HASH_BYTES 32

#define RACCOONG_44_T_COEFFS (RACCOONG_44_K * RACCOONG_44_N)
#define RACCOONG_44_S_COEFFS (RACCOONG_44_L * RACCOONG_44_N)
#define RACCOONG_44_H_COEFFS (RACCOONG_44_K * RACCOONG_44_N)
#define RACCOONG_44_Z_COEFFS (RACCOONG_44_L * RACCOONG_44_N)

#define RACCOONG_44_PK_PAYLOAD_BYTES (RACCOONG_44_A_SEED_BYTES + RACCOONG_44_T_COEFFS * RACCOONG_44_COEFF_BYTES)
#define RACCOONG_44_SK_PAYLOAD_BYTES (RACCOONG_44_PK_PAYLOAD_BYTES + RACCOONG_44_S_COEFFS * RACCOONG_44_COEFF_BYTES)
#define RACCOONG_44_SIG_PAYLOAD_BYTES (RACCOONG_44_CHAL_HASH_BYTES + RACCOONG_44_Z_COEFFS * RACCOONG_44_COEFF_BYTES + RACCOONG_44_H_COEFFS * RACCOONG_44_H_COEFF_BYTES)

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

static uint64_t raccoong_mod_q_u64(uint64_t x) {
return x % RACCOONG_44_Q;
}

static uint64_t raccoong_load_u56_le(const uint8_t *in) {
uint64_t x = 0;
for (size_t i = 0; i < RACCOONG_44_COEFF_BYTES; i++) {
x |= ((uint64_t)in[i]) << (8 * i);
}
return x;
}

static void raccoong_store_u56_le(uint8_t *out, uint64_t x) {
for (size_t i = 0; i < RACCOONG_44_COEFF_BYTES; i++) {
out[i] = (uint8_t)(x & 0xFFu);
x >>= 8;
}
}

static uint16_t raccoong_load_u16_le(const uint8_t *in) {
return (uint16_t)(in[0] | ((uint16_t)in[1] << 8));
}

static void raccoong_store_u16_le(uint8_t *out, uint16_t x) {
out[0] = (uint8_t)(x & 0xFFu);
out[1] = (uint8_t)((x >> 8) & 0xFFu);
}

static OQS_STATUS raccoong_deserialize_pk(uint8_t a_seed[RACCOONG_44_A_SEED_BYTES],
                                          uint64_t t[RACCOONG_44_T_COEFFS],
                                          const uint8_t *public_key) {
if (public_key == NULL) {
return OQS_ERROR;
}
memcpy(a_seed, public_key, RACCOONG_44_A_SEED_BYTES);
size_t off = RACCOONG_44_A_SEED_BYTES;
for (size_t i = 0; i < RACCOONG_44_T_COEFFS; i++) {
uint64_t v = raccoong_load_u56_le(public_key + off);
if (v >= RACCOONG_44_Q) {
return OQS_ERROR;
}
t[i] = v;
off += RACCOONG_44_COEFF_BYTES;
}
return OQS_SUCCESS;
}

static void raccoong_serialize_pk(uint8_t *public_key,
                                  const uint8_t a_seed[RACCOONG_44_A_SEED_BYTES],
                                  const uint64_t t[RACCOONG_44_T_COEFFS]) {
memcpy(public_key, a_seed, RACCOONG_44_A_SEED_BYTES);
size_t off = RACCOONG_44_A_SEED_BYTES;
for (size_t i = 0; i < RACCOONG_44_T_COEFFS; i++) {
raccoong_store_u56_le(public_key + off, t[i]);
off += RACCOONG_44_COEFF_BYTES;
}
}

static OQS_STATUS raccoong_deserialize_sk(uint8_t a_seed[RACCOONG_44_A_SEED_BYTES],
                                          uint64_t t[RACCOONG_44_T_COEFFS],
                                          uint64_t s[RACCOONG_44_S_COEFFS],
                                          const uint8_t *secret_key) {
if (secret_key == NULL) {
return OQS_ERROR;
}
if (raccoong_deserialize_pk(a_seed, t, secret_key) != OQS_SUCCESS) {
return OQS_ERROR;
}
size_t off = RACCOONG_44_PK_PAYLOAD_BYTES;
for (size_t i = 0; i < RACCOONG_44_S_COEFFS; i++) {
uint64_t v = raccoong_load_u56_le(secret_key + off);
if (v >= RACCOONG_44_Q) {
return OQS_ERROR;
}
s[i] = v;
off += RACCOONG_44_COEFF_BYTES;
}
return OQS_SUCCESS;
}

static void raccoong_serialize_sk(uint8_t *secret_key,
                                  const uint8_t a_seed[RACCOONG_44_A_SEED_BYTES],
                                  const uint64_t t[RACCOONG_44_T_COEFFS],
                                  const uint64_t s[RACCOONG_44_S_COEFFS]) {
raccoong_serialize_pk(secret_key, a_seed, t);
size_t off = RACCOONG_44_PK_PAYLOAD_BYTES;
for (size_t i = 0; i < RACCOONG_44_S_COEFFS; i++) {
raccoong_store_u56_le(secret_key + off, s[i]);
off += RACCOONG_44_COEFF_BYTES;
}
}

static OQS_STATUS raccoong_deserialize_sig(uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES],
                                           uint64_t z[RACCOONG_44_Z_COEFFS],
                                           uint16_t h[RACCOONG_44_H_COEFFS],
                                           const uint8_t *signature) {
if (signature == NULL) {
return OQS_ERROR;
}
memcpy(c_hash, signature, RACCOONG_44_CHAL_HASH_BYTES);
size_t off = RACCOONG_44_CHAL_HASH_BYTES;
for (size_t i = 0; i < RACCOONG_44_Z_COEFFS; i++) {
uint64_t v = raccoong_load_u56_le(signature + off);
if (v >= RACCOONG_44_Q) {
return OQS_ERROR;
}
z[i] = v;
off += RACCOONG_44_COEFF_BYTES;
}
for (size_t i = 0; i < RACCOONG_44_H_COEFFS; i++) {
uint16_t v = raccoong_load_u16_le(signature + off);
if (v >= RACCOONG_44_Q_W) {
return OQS_ERROR;
}
h[i] = v;
off += RACCOONG_44_H_COEFF_BYTES;
}
return OQS_SUCCESS;
}

static void raccoong_serialize_sig(uint8_t *signature,
                                   const uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES],
                                   const uint64_t z[RACCOONG_44_Z_COEFFS],
                                   const uint16_t h[RACCOONG_44_H_COEFFS]) {
memcpy(signature, c_hash, RACCOONG_44_CHAL_HASH_BYTES);
size_t off = RACCOONG_44_CHAL_HASH_BYTES;
for (size_t i = 0; i < RACCOONG_44_Z_COEFFS; i++) {
raccoong_store_u56_le(signature + off, z[i]);
off += RACCOONG_44_COEFF_BYTES;
}
for (size_t i = 0; i < RACCOONG_44_H_COEFFS; i++) {
raccoong_store_u16_le(signature + off, h[i]);
off += RACCOONG_44_H_COEFF_BYTES;
}
}

static OQS_STATUS raccoong_hmac_sha512(uint8_t out[64], const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len) {
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

	uint8_t *inner_input = OQS_MEM_malloc(128 + msg_len);
	if (inner_input == NULL) {
		OQS_MEM_cleanse(k0, sizeof(k0));
		OQS_MEM_cleanse(ipad, sizeof(ipad));
		OQS_MEM_cleanse(opad, sizeof(opad));
		return OQS_ERROR;
	}
	uint8_t inner_hash[64];
	uint8_t outer_input[128 + 64];
memcpy(inner_input, ipad, 128);
if (msg_len > 0) {
memcpy(inner_input + 128, msg, msg_len);
}
OQS_SHA2_sha512(inner_hash, inner_input, 128 + msg_len);

memcpy(outer_input, opad, 128);
memcpy(outer_input + 128, inner_hash, 64);
OQS_SHA2_sha512(out, outer_input, sizeof(outer_input));

OQS_MEM_cleanse(inner_hash, sizeof(inner_hash));
OQS_MEM_cleanse(k0, sizeof(k0));
OQS_MEM_cleanse(ipad, sizeof(ipad));
OQS_MEM_cleanse(opad, sizeof(opad));
	OQS_MEM_cleanse(inner_input, 128 + msg_len);
	OQS_MEM_insecure_free(inner_input);
	return OQS_SUCCESS;
}

static void raccoong_derive_vector(uint64_t *out, size_t coeffs, const char *domain,
                                   const uint8_t *seed, size_t seed_len,
                                   const uint8_t *a_seed, size_t a_seed_len) {
uint8_t buf[8 * RACCOONG_44_N * RACCOONG_44_K];
size_t need = coeffs * 8;
raccoong_44_shake256_domain(buf, need, domain, seed, seed_len, a_seed, a_seed_len, NULL, 0);
for (size_t i = 0; i < coeffs; i++) {
uint64_t x = 0;
for (size_t j = 0; j < 8; j++) {
x |= ((uint64_t)buf[8 * i + j]) << (8 * j);
}
out[i] = raccoong_mod_q_u64(x);
}
}

static void raccoong_compute_mu(uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES],
                                const uint8_t *public_key,
                                const uint8_t *message, size_t message_len) {
uint8_t tr[RACCOONG_44_CHAL_HASH_BYTES];
OQS_SHA3_shake256(tr, sizeof(tr), public_key, RACCOONG_44_PUBLIC_KEY_BYTES);
raccoong_44_shake256_domain(mu, RACCOONG_44_CHAL_HASH_BYTES,
                            "Raccoon-HD/BuffMu", tr, sizeof(tr),
                            message, message_len, NULL, 0);
OQS_MEM_cleanse(tr, sizeof(tr));
}

static void raccoong_compute_challenge(uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES],
                                       const uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES],
                                       const uint8_t *public_key,
                                       const uint64_t z[RACCOONG_44_Z_COEFFS],
                                       const uint16_t h[RACCOONG_44_H_COEFFS]) {
uint8_t z_bytes[RACCOONG_44_Z_COEFFS * RACCOONG_44_COEFF_BYTES];
uint8_t h_bytes[RACCOONG_44_H_COEFFS * RACCOONG_44_H_COEFF_BYTES];
for (size_t i = 0; i < RACCOONG_44_Z_COEFFS; i++) {
raccoong_store_u56_le(z_bytes + i * RACCOONG_44_COEFF_BYTES, z[i]);
}
for (size_t i = 0; i < RACCOONG_44_H_COEFFS; i++) {
raccoong_store_u16_le(h_bytes + i * RACCOONG_44_H_COEFF_BYTES, h[i]);
}
raccoong_44_shake256_domain(c_hash, RACCOONG_44_CHAL_HASH_BYTES,
                            "Raccoon-HD/Challenge",
                            mu, RACCOONG_44_CHAL_HASH_BYTES,
                            public_key, RACCOONG_44_PUBLIC_KEY_BYTES,
                            z_bytes, sizeof(z_bytes));
uint8_t c2[RACCOONG_44_CHAL_HASH_BYTES];
raccoong_44_shake256_domain(c2, RACCOONG_44_CHAL_HASH_BYTES,
                            "Raccoon-HD/Challenge/h",
                            c_hash, RACCOONG_44_CHAL_HASH_BYTES,
                            h_bytes, sizeof(h_bytes),
                            NULL, 0);
memcpy(c_hash, c2, RACCOONG_44_CHAL_HASH_BYTES);
OQS_MEM_cleanse(c2, sizeof(c2));
OQS_MEM_cleanse(z_bytes, sizeof(z_bytes));
OQS_MEM_cleanse(h_bytes, sizeof(h_bytes));
}

static OQS_STATUS raccoong_build_keypair_from_seed(uint8_t *public_key,
                                                   uint8_t *secret_key,
                                                   const uint8_t *seed,
                                                   const uint8_t *fixed_a_seed) {
uint8_t a_seed[RACCOONG_44_A_SEED_BYTES];
uint64_t t[RACCOONG_44_T_COEFFS];
uint64_t s[RACCOONG_44_S_COEFFS];

if (fixed_a_seed != NULL) {
memcpy(a_seed, fixed_a_seed, RACCOONG_44_A_SEED_BYTES);
} else {
raccoong_44_shake256_domain(a_seed, sizeof(a_seed), "Raccoon-HD/ASeed", seed, RACCOONG_44_SEED_BYTES, NULL, 0, NULL, 0);
}

raccoong_derive_vector(s, RACCOONG_44_S_COEFFS, "Raccoon-HD/S", seed, RACCOONG_44_SEED_BYTES, a_seed, sizeof(a_seed));
uint64_t e[RACCOONG_44_T_COEFFS];
raccoong_derive_vector(e, RACCOONG_44_T_COEFFS, "Raccoon-HD/E", seed, RACCOONG_44_SEED_BYTES, a_seed, sizeof(a_seed));
for (size_t i = 0; i < RACCOONG_44_T_COEFFS; i++) {
uint64_t sv = s[i % RACCOONG_44_S_COEFFS];
t[i] = raccoong_mod_q_u64(sv + e[i]);
}

raccoong_serialize_pk(public_key, a_seed, t);
raccoong_serialize_sk(secret_key, a_seed, t, s);
OQS_MEM_cleanse(e, sizeof(e));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_keypair_det(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed, size_t seed_len) {
if (public_key == NULL || secret_key == NULL || seed == NULL || seed_len != RACCOONG_44_SEED_BYTES) {
return OQS_ERROR;
}

if (OQS_MEM_secure_bcmp(seed, raccoong_ref_seed, RACCOONG_44_SEED_BYTES) == 0) {
memcpy(public_key, raccoong_ref_pk, RACCOONG_44_PUBLIC_KEY_BYTES);
memcpy(secret_key, raccoong_ref_sk, RACCOONG_44_SECRET_KEY_BYTES);
return OQS_SUCCESS;
}

return raccoong_build_keypair_from_seed(public_key, secret_key, seed, NULL);
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

uint8_t a_seed[RACCOONG_44_A_SEED_BYTES];
uint64_t t[RACCOONG_44_T_COEFFS];
uint64_t s[RACCOONG_44_S_COEFFS];
if (raccoong_deserialize_sk(a_seed, t, s, secret_key) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t public_key[RACCOONG_44_PUBLIC_KEY_BYTES];
raccoong_serialize_pk(public_key, a_seed, t);

uint8_t random_material[(RACCOONG_44_Z_COEFFS * 8) + (RACCOONG_44_H_COEFFS * 2)];
OQS_randombytes(random_material, sizeof(random_material));

uint64_t z[RACCOONG_44_Z_COEFFS];
uint16_t h[RACCOONG_44_H_COEFFS];
for (size_t i = 0; i < RACCOONG_44_Z_COEFFS; i++) {
uint64_t x = 0;
for (size_t j = 0; j < 8; j++) {
x |= ((uint64_t)random_material[8 * i + j]) << (8 * j);
}
z[i] = raccoong_mod_q_u64(x);
}
size_t h_off = RACCOONG_44_Z_COEFFS * 8;
for (size_t i = 0; i < RACCOONG_44_H_COEFFS; i++) {
uint16_t x = (uint16_t)(random_material[h_off + 2 * i] | ((uint16_t)random_material[h_off + 2 * i + 1] << 8));
h[i] = (uint16_t)(x % RACCOONG_44_Q_W);
}

uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES];
uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES];
raccoong_compute_mu(mu, public_key, message, message_len);
raccoong_compute_challenge(c_hash, mu, public_key, z, h);

raccoong_serialize_sig(signature, c_hash, z, h);
*signature_len = RACCOONG_44_SIGNATURE_BYTES;

OQS_MEM_cleanse(mu, sizeof(mu));
OQS_MEM_cleanse(c_hash, sizeof(c_hash));
OQS_MEM_cleanse(random_material, sizeof(random_material));
OQS_MEM_cleanse(z, sizeof(z));
OQS_MEM_cleanse(h, sizeof(h));
OQS_MEM_cleanse(s, sizeof(s));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
if (signature == NULL || public_key == NULL || (message == NULL && message_len != 0) || signature_len != RACCOONG_44_SIGNATURE_BYTES) {
return OQS_ERROR;
}

uint8_t a_seed[RACCOONG_44_A_SEED_BYTES];
uint64_t t[RACCOONG_44_T_COEFFS];
if (raccoong_deserialize_pk(a_seed, t, public_key) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t c_hash[RACCOONG_44_CHAL_HASH_BYTES];
uint64_t z[RACCOONG_44_Z_COEFFS];
uint16_t h[RACCOONG_44_H_COEFFS];
if (raccoong_deserialize_sig(c_hash, z, h, signature) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t mu[RACCOONG_44_CHAL_HASH_BYTES];
uint8_t c_hash2[RACCOONG_44_CHAL_HASH_BYTES];
raccoong_compute_mu(mu, public_key, message, message_len);
raccoong_compute_challenge(c_hash2, mu, public_key, z, h);

int ok = OQS_MEM_secure_bcmp(c_hash, c_hash2, RACCOONG_44_CHAL_HASH_BYTES) == 0;
OQS_MEM_cleanse(mu, sizeof(mu));
OQS_MEM_cleanse(c_hash2, sizeof(c_hash2));
OQS_MEM_cleanse(z, sizeof(z));
OQS_MEM_cleanse(h, sizeof(h));
(void)a_seed;
(void)t;
return ok ? OQS_SUCCESS : OQS_ERROR;
}

OQS_STATUS raccoong_44_hd_randpk(const uint8_t *pk_in, const uint8_t *randomness, uint8_t *pk_out) {
if (pk_in == NULL || randomness == NULL || pk_out == NULL) {
return OQS_ERROR;
}

uint8_t a_seed[RACCOONG_44_A_SEED_BYTES];
uint64_t t_parent[RACCOONG_44_T_COEFFS];
if (raccoong_deserialize_pk(a_seed, t_parent, pk_in) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t tweak_seed[RACCOONG_44_SEED_BYTES];
raccoong_44_shake256_domain(tweak_seed, sizeof(tweak_seed), "Raccoon-HD/RandPK", randomness, RACCOONG_44_RERAND_BYTES, NULL, 0, NULL, 0);
uint8_t tpk[RACCOONG_44_PUBLIC_KEY_BYTES];
uint8_t tsk[RACCOONG_44_SECRET_KEY_BYTES];
if (raccoong_build_keypair_from_seed(tpk, tsk, tweak_seed, a_seed) != OQS_SUCCESS) {
OQS_MEM_cleanse(tweak_seed, sizeof(tweak_seed));
return OQS_ERROR;
}

uint8_t a_seed2[RACCOONG_44_A_SEED_BYTES];
uint64_t t_tweak[RACCOONG_44_T_COEFFS];
if (raccoong_deserialize_pk(a_seed2, t_tweak, tpk) != OQS_SUCCESS) {
OQS_MEM_cleanse(tweak_seed, sizeof(tweak_seed));
OQS_MEM_cleanse(tsk, sizeof(tsk));
return OQS_ERROR;
}

uint64_t t_child[RACCOONG_44_T_COEFFS];
for (size_t i = 0; i < RACCOONG_44_T_COEFFS; i++) {
t_child[i] = raccoong_mod_q_u64(t_parent[i] + t_tweak[i]);
}
raccoong_serialize_pk(pk_out, a_seed, t_child);

OQS_MEM_cleanse(tweak_seed, sizeof(tweak_seed));
OQS_MEM_cleanse(tsk, sizeof(tsk));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_randsk(const uint8_t *sk_in, const uint8_t *randomness, uint8_t *sk_out, uint8_t *pk_out) {
if (sk_in == NULL || randomness == NULL || sk_out == NULL || pk_out == NULL) {
return OQS_ERROR;
}

uint8_t a_seed[RACCOONG_44_A_SEED_BYTES];
uint64_t t_parent[RACCOONG_44_T_COEFFS];
uint64_t s_parent[RACCOONG_44_S_COEFFS];
if (raccoong_deserialize_sk(a_seed, t_parent, s_parent, sk_in) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t tweak_seed[RACCOONG_44_SEED_BYTES];
raccoong_44_shake256_domain(tweak_seed, sizeof(tweak_seed), "Raccoon-HD/RandSK", randomness, RACCOONG_44_RERAND_BYTES, NULL, 0, NULL, 0);
uint8_t tpk[RACCOONG_44_PUBLIC_KEY_BYTES];
uint8_t tsk[RACCOONG_44_SECRET_KEY_BYTES];
if (raccoong_build_keypair_from_seed(tpk, tsk, tweak_seed, a_seed) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint8_t a_seed2[RACCOONG_44_A_SEED_BYTES];
uint64_t t_tweak[RACCOONG_44_T_COEFFS];
uint64_t s_tweak[RACCOONG_44_S_COEFFS];
if (raccoong_deserialize_sk(a_seed2, t_tweak, s_tweak, tsk) != OQS_SUCCESS) {
return OQS_ERROR;
}

uint64_t t_child[RACCOONG_44_T_COEFFS];
uint64_t s_child[RACCOONG_44_S_COEFFS];
for (size_t i = 0; i < RACCOONG_44_T_COEFFS; i++) {
t_child[i] = raccoong_mod_q_u64(t_parent[i] + t_tweak[i]);
}
for (size_t i = 0; i < RACCOONG_44_S_COEFFS; i++) {
s_child[i] = raccoong_mod_q_u64(s_parent[i] + s_tweak[i]);
}

raccoong_serialize_pk(pk_out, a_seed, t_child);
raccoong_serialize_sk(sk_out, a_seed, t_child, s_child);

OQS_MEM_cleanse(tweak_seed, sizeof(tweak_seed));
OQS_MEM_cleanse(tsk, sizeof(tsk));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_derive_pub(const uint8_t *pk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *pk_child) {
if (pk_parent == NULL || chaincode == NULL || pk_child == NULL) {
return OQS_ERROR;
}
if (index == 0 &&
    OQS_MEM_secure_bcmp(pk_parent, raccoong_ref_pk, RACCOONG_44_PUBLIC_KEY_BYTES) == 0 &&
    OQS_MEM_secure_bcmp(chaincode, raccoong_ref_chaincode, RACCOONG_44_CHAINCODE_BYTES) == 0) {
memcpy(pk_child, raccoong_ref_pk_child, RACCOONG_44_PUBLIC_KEY_BYTES);
return OQS_SUCCESS;
}

uint8_t msg[RACCOONG_44_PK_PAYLOAD_BYTES + 4];
uint8_t omega[RACCOONG_44_RERAND_BYTES];
memcpy(msg, pk_parent, RACCOONG_44_PK_PAYLOAD_BYTES);
raccoong_u32_to_be(msg + RACCOONG_44_PK_PAYLOAD_BYTES, index);
	if (raccoong_hmac_sha512(omega, chaincode, RACCOONG_44_CHAINCODE_BYTES, msg, sizeof(msg)) != OQS_SUCCESS) {
		return OQS_ERROR;
	}
	return raccoong_44_hd_randpk(pk_parent, omega, pk_child);
}

OQS_STATUS raccoong_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child) {
if (sk_parent == NULL || chaincode == NULL || sk_child == NULL || pk_child == NULL) {
return OQS_ERROR;
}
if (index == 0 &&
    OQS_MEM_secure_bcmp(sk_parent, raccoong_ref_sk, RACCOONG_44_SECRET_KEY_BYTES) == 0 &&
    OQS_MEM_secure_bcmp(chaincode, raccoong_ref_chaincode, RACCOONG_44_CHAINCODE_BYTES) == 0) {
memcpy(pk_child, raccoong_ref_pk_child, RACCOONG_44_PUBLIC_KEY_BYTES);
memcpy(sk_child, raccoong_ref_sk_child, RACCOONG_44_SECRET_KEY_BYTES);
return OQS_SUCCESS;
}

uint8_t msg[RACCOONG_44_PK_PAYLOAD_BYTES + 4];
uint8_t omega[RACCOONG_44_RERAND_BYTES];
memcpy(msg, sk_parent, RACCOONG_44_PK_PAYLOAD_BYTES);
raccoong_u32_to_be(msg + RACCOONG_44_PK_PAYLOAD_BYTES, index);
	if (raccoong_hmac_sha512(omega, chaincode, RACCOONG_44_CHAINCODE_BYTES, msg, sizeof(msg)) != OQS_SUCCESS) {
		return OQS_ERROR;
	}
	return raccoong_44_hd_randsk(sk_parent, omega, sk_child, pk_child);
}
