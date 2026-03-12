// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/sig_raccoong.h>

#include "raccoong.h"

#if defined(OQS_ENABLE_SIG_raccoon_g_44)
OQS_SIG *OQS_SIG_raccoon_g_44_new(void) {
OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
if (sig == NULL) {
return NULL;
}

sig->method_name = OQS_SIG_alg_raccoon_g_44;
sig->alg_version = "Raccoon-G draft (liboqs integrated)";
sig->claimed_nist_level = 2;
sig->euf_cma = true;
sig->suf_cma = true;
sig->sig_with_ctx_support = false;

sig->length_public_key = OQS_SIG_raccoon_g_44_length_public_key;
sig->length_secret_key = OQS_SIG_raccoon_g_44_length_secret_key;
sig->length_signature = OQS_SIG_raccoon_g_44_length_signature;

sig->keypair = OQS_SIG_raccoon_g_44_keypair;
sig->sign = OQS_SIG_raccoon_g_44_sign;
sig->verify = OQS_SIG_raccoon_g_44_verify;
sig->sign_with_ctx_str = OQS_SIG_raccoon_g_44_sign_with_ctx_str;
sig->verify_with_ctx_str = OQS_SIG_raccoon_g_44_verify_with_ctx_str;

return sig;
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
return raccoong_44_keypair(public_key, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_keypair_det(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed, size_t seed_len) {
return raccoong_44_keypair_det(public_key, secret_key, seed, seed_len);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
return raccoong_44_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
return raccoong_44_verify(message, message_len, signature, signature_len, public_key);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key) {
if (ctx == NULL && ctxlen == 0) {
return OQS_SIG_raccoon_g_44_sign(signature, signature_len, message, message_len, secret_key);
}
return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key) {
if (ctx == NULL && ctxlen == 0) {
return OQS_SIG_raccoon_g_44_verify(message, message_len, signature, signature_len, public_key);
}
return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_derive_pub(const uint8_t *pk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *pk_child) {
return raccoong_44_hd_derive_pub(pk_parent, chaincode, index, pk_child);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child) {
return raccoong_44_hd_derive_priv(sk_parent, chaincode, index, sk_child, pk_child);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_randpk(const uint8_t *pk_in, const uint8_t *randomness, uint8_t *pk_out) {
return raccoong_44_hd_randpk(pk_in, randomness, pk_out);
}

OQS_API OQS_STATUS OQS_SIG_raccoon_g_44_hd_randsk(const uint8_t *sk_in, const uint8_t *randomness, uint8_t *sk_out, uint8_t *pk_out) {
return raccoong_44_hd_randsk(sk_in, randomness, sk_out, pk_out);
}
#endif
