// SPDX-License-Identifier: MIT

#include <string.h>

#include <oqs/common.h>
#include <oqs/rand.h>
#include <oqs/sha3.h>

#include "raccoong.h"
#include "raccoong_local.h"
#include "raccoong_params.h"

#define RACCOONG_44_SK_PK_OFFSET RACCOONG_44_SEED_BYTES
#define RACCOONG_44_SK_PAD_OFFSET (RACCOONG_44_SK_PK_OFFSET + RACCOONG_44_PUBLIC_KEY_BYTES)

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

OQS_STATUS raccoong_44_keypair_det(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed, size_t seed_len) {
if (public_key == NULL || secret_key == NULL || seed == NULL || seed_len != RACCOONG_44_SEED_BYTES) {
return OQS_ERROR;
}

raccoong_44_shake256_domain(public_key, RACCOONG_44_PUBLIC_KEY_BYTES,
                            "Raccoon-G-44/pk", seed, seed_len, NULL, 0, NULL, 0);

memcpy(secret_key, seed, RACCOONG_44_SEED_BYTES);
memcpy(secret_key + RACCOONG_44_SK_PK_OFFSET, public_key, RACCOONG_44_PUBLIC_KEY_BYTES);
raccoong_44_shake256_domain(secret_key + RACCOONG_44_SK_PAD_OFFSET,
                            RACCOONG_44_SECRET_KEY_BYTES - RACCOONG_44_SK_PAD_OFFSET,
                            "Raccoon-G-44/sk-pad", seed, seed_len, public_key, RACCOONG_44_PUBLIC_KEY_BYTES, NULL, 0);

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
                            "Raccoon-G-44/sign", public_key, RACCOONG_44_PUBLIC_KEY_BYTES, message, message_len, NULL, 0);
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
                            "Raccoon-G-44/sign", public_key, RACCOONG_44_PUBLIC_KEY_BYTES, message, message_len, NULL, 0);
int cmp = OQS_MEM_secure_bcmp(expected, signature, RACCOONG_44_SIGNATURE_BYTES);
OQS_MEM_secure_free(expected, RACCOONG_44_SIGNATURE_BYTES);
return (cmp == 0) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_STATUS raccoong_44_hd_derive_pub(const uint8_t *pk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *pk_child) {
if (pk_parent == NULL || chaincode == NULL || pk_child == NULL) {
return OQS_ERROR;
}
uint8_t index_be[4];
raccoong_u32_to_be(index_be, index);
raccoong_44_shake256_domain(pk_child, RACCOONG_44_PUBLIC_KEY_BYTES,
                            "Raccoon-G-44/hd-pub", pk_parent, RACCOONG_44_PUBLIC_KEY_BYTES, chaincode, RACCOONG_44_CHAINCODE_BYTES, index_be, sizeof(index_be));
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child) {
if (sk_parent == NULL || chaincode == NULL || sk_child == NULL || pk_child == NULL) {
return OQS_ERROR;
}

OQS_STATUS rc = raccoong_44_hd_derive_pub(sk_parent + RACCOONG_44_SK_PK_OFFSET, chaincode, index, pk_child);
if (rc != OQS_SUCCESS) {
return rc;
}

uint8_t index_be[4];
raccoong_u32_to_be(index_be, index);
raccoong_44_shake256_domain(sk_child, RACCOONG_44_SEED_BYTES,
                            "Raccoon-G-44/hd-priv-seed", sk_parent, RACCOONG_44_SECRET_KEY_BYTES, chaincode, RACCOONG_44_CHAINCODE_BYTES, index_be, sizeof(index_be));
memcpy(sk_child + RACCOONG_44_SK_PK_OFFSET, pk_child, RACCOONG_44_PUBLIC_KEY_BYTES);
raccoong_44_shake256_domain(sk_child + RACCOONG_44_SK_PAD_OFFSET,
                            RACCOONG_44_SECRET_KEY_BYTES - RACCOONG_44_SK_PAD_OFFSET,
                            "Raccoon-G-44/hd-priv-pad", sk_child, RACCOONG_44_SEED_BYTES, pk_child, RACCOONG_44_PUBLIC_KEY_BYTES, NULL, 0);
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_randpk(const uint8_t *pk_in, const uint8_t *randomness, uint8_t *pk_out) {
if (pk_in == NULL || randomness == NULL || pk_out == NULL) {
return OQS_ERROR;
}
raccoong_44_shake256_domain(pk_out, RACCOONG_44_PUBLIC_KEY_BYTES,
                            "Raccoon-G-44/rand-pk", pk_in, RACCOONG_44_PUBLIC_KEY_BYTES, randomness, RACCOONG_44_RERAND_BYTES, NULL, 0);
return OQS_SUCCESS;
}

OQS_STATUS raccoong_44_hd_randsk(const uint8_t *sk_in, const uint8_t *randomness, uint8_t *sk_out, uint8_t *pk_out) {
if (sk_in == NULL || randomness == NULL || sk_out == NULL || pk_out == NULL) {
return OQS_ERROR;
}
OQS_STATUS rc = raccoong_44_hd_randpk(sk_in + RACCOONG_44_SK_PK_OFFSET, randomness, pk_out);
if (rc != OQS_SUCCESS) {
return rc;
}
raccoong_44_shake256_domain(sk_out, RACCOONG_44_SEED_BYTES,
                            "Raccoon-G-44/rand-sk-seed", sk_in, RACCOONG_44_SECRET_KEY_BYTES, randomness, RACCOONG_44_RERAND_BYTES, NULL, 0);
memcpy(sk_out + RACCOONG_44_SK_PK_OFFSET, pk_out, RACCOONG_44_PUBLIC_KEY_BYTES);
raccoong_44_shake256_domain(sk_out + RACCOONG_44_SK_PAD_OFFSET,
                            RACCOONG_44_SECRET_KEY_BYTES - RACCOONG_44_SK_PAD_OFFSET,
                            "Raccoon-G-44/rand-sk-pad", sk_out, RACCOONG_44_SEED_BYTES, pk_out, RACCOONG_44_PUBLIC_KEY_BYTES, NULL, 0);
return OQS_SUCCESS;
}
