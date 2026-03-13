// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>
#include <oqs/sha2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(int ok, const char *msg) {
if (!ok) {
fprintf(stderr, "%s\n", msg);
return EXIT_FAILURE;
}
return EXIT_SUCCESS;
}

static int check_sha256(const uint8_t *buf, size_t len, const uint8_t expected[32], const char *msg) {
	uint8_t digest[32];
	OQS_SHA2_sha256(digest, buf, len);
	return check(OQS_MEM_secure_bcmp(digest, expected, sizeof(digest)) == 0, msg);
}

int main(void) {
OQS_init();

#ifndef OQS_ENABLE_SIG_raccoon_g_44
printf("Raccoon-G-44 not enabled at compile-time.\n");
OQS_destroy();
return EXIT_SUCCESS;
#else
	/*
	 * Deterministic reproducibility anchors derived from the implemented
	 * ePrint 2026/380 Section 4/5 algorithm flow.
	 * Note: the paper's appendices stop at A/B/C and do not include
	 * canonical vector hex dumps.
	 */
const uint8_t master_seed[32] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
const uint8_t chaincode[OQS_SIG_raccoon_g_44_length_chaincode] = {0};
const uint8_t msg[] = "test message";
const uint8_t expected_pk_sha256[32] = {
0x73, 0xfd, 0x4b, 0xe0, 0x94, 0xb2, 0xbf, 0xfb,
0x78, 0xa9, 0x43, 0x64, 0x02, 0xdd, 0xfa, 0xfe,
0xef, 0x31, 0xdc, 0x47, 0x7d, 0xe4, 0x00, 0xb9,
0x39, 0x66, 0x71, 0xa8, 0xc9, 0xe8, 0x1d, 0x6b
};
const uint8_t expected_sk_sha256[32] = {
0x6b, 0x6b, 0xa8, 0x76, 0x06, 0x40, 0x62, 0xad,
0xde, 0x66, 0xb8, 0xf1, 0x0e, 0xdb, 0xd7, 0x7f,
0x55, 0x40, 0xf3, 0x78, 0x42, 0x42, 0x29, 0x64,
0xda, 0xc3, 0xdd, 0x2b, 0xe3, 0xce, 0x95, 0xe4
};
const uint8_t expected_pk_child_sha256[32] = {
0xd7, 0x21, 0x2a, 0xee, 0x12, 0xb8, 0xcb, 0xb9,
0x7a, 0xc5, 0xcc, 0xf9, 0xac, 0xa0, 0xc1, 0x73,
0x7c, 0xb7, 0x91, 0xdf, 0x1a, 0xce, 0xf3, 0x18,
0x02, 0x66, 0x20, 0x9e, 0xfb, 0xe0, 0xf2, 0x5a
};
const uint8_t expected_sk_child_sha256[32] = {
0x81, 0xab, 0x98, 0x24, 0xad, 0x80, 0x30, 0xf3,
0x17, 0x5b, 0x26, 0xf7, 0x0d, 0x4a, 0x29, 0x19,
0x32, 0x92, 0x38, 0x85, 0xc4, 0xe5, 0x56, 0xeb,
0x10, 0xc9, 0xb5, 0x5b, 0x75, 0xbd, 0x5b, 0x17
};
const uint8_t expected_sig_master_sha256[32] = {
0xc6, 0xb4, 0x84, 0x57, 0x3a, 0x45, 0x9c, 0x08,
0xbe, 0x95, 0xd7, 0x4e, 0x72, 0x5e, 0x44, 0xed,
0x61, 0x09, 0xfd, 0xfd, 0x9c, 0x39, 0x20, 0x15,
0x83, 0xa7, 0x8c, 0xf5, 0xc4, 0x86, 0x5a, 0xea
};
const uint8_t expected_sig_child_sha256[32] = {
0x7f, 0xdd, 0x29, 0x83, 0xc1, 0x63, 0x8d, 0xe5,
0xf0, 0xaf, 0xc6, 0x27, 0x6f, 0x7c, 0xcb, 0x2c,
0xea, 0xc9, 0x40, 0x6a, 0x67, 0xb6, 0x37, 0x9b,
0xc1, 0x64, 0xe7, 0x6c, 0x05, 0x02, 0xd3, 0xdf
};
const size_t pk_payload_bytes = (size_t)(4 * 4 + 4) * 256 * 3;
const size_t sk_payload_bytes = (size_t)(4 + 4) * 256 * 3 + OQS_SIG_raccoon_g_44_length_public_key;

uint8_t pk[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t sk[OQS_SIG_raccoon_g_44_length_secret_key];
uint8_t pk_child_pub[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t pk_child_pub_noncanonical[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t pk_child_priv[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t sk_child[OQS_SIG_raccoon_g_44_length_secret_key];
uint8_t sig_master[OQS_SIG_raccoon_g_44_length_signature];
uint8_t sig_child[OQS_SIG_raccoon_g_44_length_signature];
uint8_t pk_noncanonical[OQS_SIG_raccoon_g_44_length_public_key];
size_t sig_master_len = 0, sig_child_len = 0;

if (check(OQS_SIG_raccoon_g_44_keypair_det(pk, sk, master_seed, sizeof(master_seed)) == OQS_SUCCESS,
          "Raccoon-G-44 DetKeyGen vector failed") != EXIT_SUCCESS) {
goto err;
}
if (check_sha256(pk, sizeof(pk), expected_pk_sha256, "DetKeyGen vector drift: PK SHA-256 mismatch") != EXIT_SUCCESS) {
goto err;
}
if (check_sha256(sk, sizeof(sk), expected_sk_sha256, "DetKeyGen vector drift: SK SHA-256 mismatch") != EXIT_SUCCESS) {
goto err;
}
OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_raccoon_g_44);
if (check(sig != NULL, "OQS_SIG_new(Raccoon-G-44) failed") != EXIT_SUCCESS) {
goto err;
}
if (check(sig->length_public_key == OQS_SIG_raccoon_g_44_length_public_key &&
          sig->length_public_key == 16384,
          "Binary compatibility failure: public key size changed") != EXIT_SUCCESS) {
OQS_SIG_free(sig);
goto err;
}
if (check(sig->length_secret_key == OQS_SIG_raccoon_g_44_length_secret_key &&
          sig->length_secret_key == 32768,
          "Binary compatibility failure: secret key size changed") != EXIT_SUCCESS) {
OQS_SIG_free(sig);
goto err;
}
if (check(sig->length_signature == OQS_SIG_raccoon_g_44_length_signature &&
          sig->length_signature == 32768,
          "Binary compatibility failure: signature size changed") != EXIT_SUCCESS) {
OQS_SIG_free(sig);
goto err;
}
OQS_SIG_free(sig);
if (check(pk_payload_bytes < sizeof(pk) &&
          sk_payload_bytes < sizeof(sk),
          "Internal test assumptions invalid for Raccoon-G-44 payload sizes") != EXIT_SUCCESS) {
goto err;
}
for (size_t i = pk_payload_bytes; i < sizeof(pk); i++) {
if (check(pk[i] == 0, "Binary compatibility failure: PK padding is not canonical zero") != EXIT_SUCCESS) {
goto err;
}
}
for (size_t i = sk_payload_bytes; i < sizeof(sk); i++) {
if (check(sk[i] == 0, "Binary compatibility failure: SK padding is not canonical zero") != EXIT_SUCCESS) {
goto err;
}
}
memcpy(pk_noncanonical, pk, sizeof(pk_noncanonical));
memset(pk_noncanonical + pk_payload_bytes, 0xA5, sizeof(pk_noncanonical) - pk_payload_bytes);

if (check(OQS_SIG_hd_derive_pub(pk, chaincode, 0, pk_child_pub) == OQS_SUCCESS,
          "CKDer_pub vector failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_hd_derive_pub(pk_noncanonical, chaincode, 0, pk_child_pub_noncanonical) == OQS_SUCCESS,
          "CKDer_pub with non-canonical PK padding failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_MEM_secure_bcmp(pk_child_pub, pk_child_pub_noncanonical, sizeof(pk_child_pub)) == 0,
          "HD derivation must ignore reserved PK padding bytes") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_hd_derive_priv(sk, chaincode, 0, sk_child, pk_child_priv) == OQS_SUCCESS,
          "CKDer_priv vector failed") != EXIT_SUCCESS) {
goto err;
}
if (check_sha256(pk_child_pub, sizeof(pk_child_pub), expected_pk_child_sha256, "CKDer vector drift: child PK SHA-256 mismatch") != EXIT_SUCCESS) {
goto err;
}
if (check_sha256(sk_child, sizeof(sk_child), expected_sk_child_sha256, "CKDer vector drift: child SK SHA-256 mismatch") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_MEM_secure_bcmp(pk_child_pub, pk_child_priv, sizeof(pk_child_pub)) == 0,
          "Public derivation mismatch: CKDer_pub != CKDer_priv path") != EXIT_SUCCESS) {
goto err;
}

if (check(OQS_SIG_raccoon_g_44_sign(sig_master, &sig_master_len, msg, sizeof(msg) - 1, sk) == OQS_SUCCESS,
          "Master signature generation failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_master, sig_master_len, pk) == OQS_SUCCESS,
          "Master signature verification failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_master, sig_master_len, pk_noncanonical) == OQS_SUCCESS,
          "Master signature verification must ignore reserved PK padding bytes") != EXIT_SUCCESS) {
goto err;
}
if (check_sha256(sig_master, sig_master_len, expected_sig_master_sha256, "Sign vector drift: master signature SHA-256 mismatch") != EXIT_SUCCESS) {
goto err;
}

if (check(OQS_SIG_raccoon_g_44_sign(sig_child, &sig_child_len, msg, sizeof(msg) - 1, sk_child) == OQS_SUCCESS,
          "Child signature generation failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_child, sig_child_len, pk_child_pub) == OQS_SUCCESS,
          "Child signature verification failed") != EXIT_SUCCESS) {
goto err;
}
if (check_sha256(sig_child, sig_child_len, expected_sig_child_sha256, "Sign vector drift: child signature SHA-256 mismatch") != EXIT_SUCCESS) {
goto err;
}

	printf("Raccoon-G-44 deterministic vector tests passed.\n");
OQS_destroy();
return EXIT_SUCCESS;

err:
OQS_destroy();
return EXIT_FAILURE;
#endif
}
