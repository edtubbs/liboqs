// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>

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

if (check(OQS_SIG_raccoon_g_44_sign(sig_child, &sig_child_len, msg, sizeof(msg) - 1, sk_child) == OQS_SUCCESS,
          "Child signature generation failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_child, sig_child_len, pk_child_pub) == OQS_SUCCESS,
          "Child signature verification failed") != EXIT_SUCCESS) {
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
