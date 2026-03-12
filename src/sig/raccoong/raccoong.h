// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_RACCOONG_CORE_H
#define OQS_SIG_RACCOONG_CORE_H

#include <oqs/oqs.h>

OQS_STATUS raccoong_44_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS raccoong_44_keypair_det(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed, size_t seed_len);
OQS_STATUS raccoong_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_STATUS raccoong_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_STATUS raccoong_44_hd_derive_pub(const uint8_t *pk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *pk_child);
OQS_STATUS raccoong_44_hd_derive_priv(const uint8_t *sk_parent, const uint8_t *chaincode, uint32_t index, uint8_t *sk_child, uint8_t *pk_child);
OQS_STATUS raccoong_44_hd_randpk(const uint8_t *pk_in, const uint8_t *randomness, uint8_t *pk_out);
OQS_STATUS raccoong_44_hd_randsk(const uint8_t *sk_in, const uint8_t *randomness, uint8_t *sk_out, uint8_t *pk_out);

#endif // OQS_SIG_RACCOONG_CORE_H
