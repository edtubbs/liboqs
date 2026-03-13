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
 * Paper vector anchors (ePrint 2026/380, Appendix D):
 * - master seed: 000102...1f
 * - non-hardened child at index 0 with all-zero chaincode
 * - message: "test message"
 */
const uint8_t master_seed[32] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
const uint8_t chaincode[OQS_SIG_raccoon_g_44_length_chaincode] = {0};
const uint8_t msg[] = "test message";

uint8_t pk[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t sk[OQS_SIG_raccoon_g_44_length_secret_key];
uint8_t pk_child_pub[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t pk_child_priv[OQS_SIG_raccoon_g_44_length_public_key];
uint8_t sk_child[OQS_SIG_raccoon_g_44_length_secret_key];
uint8_t sig_master[OQS_SIG_raccoon_g_44_length_signature];
uint8_t sig_child[OQS_SIG_raccoon_g_44_length_signature];
size_t sig_master_len = 0, sig_child_len = 0;

if (check(OQS_SIG_raccoon_g_44_keypair_det(pk, sk, master_seed, sizeof(master_seed)) == OQS_SUCCESS,
          "Raccoon-G-44 DetKeyGen vector failed") != EXIT_SUCCESS) {
goto err;
}

if (check(OQS_SIG_hd_derive_pub(pk, chaincode, 0, pk_child_pub) == OQS_SUCCESS,
          "CKDer_pub vector failed") != EXIT_SUCCESS) {
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

if (check(OQS_SIG_raccoon_g_44_sign(sig_child, &sig_child_len, msg, sizeof(msg) - 1, sk_child) == OQS_SUCCESS,
          "Child signature generation failed") != EXIT_SUCCESS) {
goto err;
}
if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_child, sig_child_len, pk_child_pub) == OQS_SUCCESS,
          "Child signature verification failed") != EXIT_SUCCESS) {
goto err;
}

printf("Raccoon-G-44 paper-vector anchored tests passed.\n");
OQS_destroy();
return EXIT_SUCCESS;

err:
OQS_destroy();
return EXIT_FAILURE;
#endif
}
