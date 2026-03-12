// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_RACCOONG_API_H
#define OQS_SIG_RACCOONG_API_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_raccoon_g_44)
#ifndef OQS_ENABLE_SIG_RACCOON_G_44
#define OQS_ENABLE_SIG_RACCOON_G_44 1
#endif

#define OQS_SIG_raccoon_g_44_length_public_key 16384
#define OQS_SIG_raccoon_g_44_length_secret_key 32768
#define OQS_SIG_raccoon_g_44_length_signature 32768
#define OQS_SIG_raccoon_g_44_length_keypair_seed 64
#define OQS_SIG_raccoon_g_44_length_chaincode 32
#define OQS_SIG_raccoon_g_44_length_rerandomization 32

OQS_SIG *OQS_SIG_raccoon_g_44_new(void);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_keypair_det(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed, size_t seed_len);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_derive_pub(const uint8_t *pk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *pk_child);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_randpk(const uint8_t *pk_in, const uint8_t *randomness, uint8_t *pk_out);
OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_randsk(const uint8_t *sk_in, const uint8_t *randomness, uint8_t *sk_out, uint8_t *pk_out);

#endif

#endif
