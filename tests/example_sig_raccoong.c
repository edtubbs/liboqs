// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
	OQS_init();

#ifdef OQS_ENABLE_SIG_raccoon_g_44
	uint8_t pk[OQS_SIG_raccoon_g_44_length_public_key];
	uint8_t sk[OQS_SIG_raccoon_g_44_length_secret_key];
	uint8_t msg[32] = {0};
	uint8_t sig[OQS_SIG_raccoon_g_44_length_signature];
	size_t sig_len = 0;
	uint8_t chaincode[OQS_SIG_raccoon_g_44_length_chaincode] = {0};
	uint8_t pk_child[OQS_SIG_raccoon_g_44_length_public_key];
	uint8_t sk_child[OQS_SIG_raccoon_g_44_length_secret_key];
	uint8_t pk_child_from_sk[OQS_SIG_raccoon_g_44_length_public_key];

	if (OQS_SIG_raccoon_g_44_keypair(pk, sk) != OQS_SUCCESS) {
		fprintf(stderr, "Raccoon-G-44 keypair failed\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}
	if (OQS_SIG_raccoon_g_44_sign(sig, &sig_len, msg, sizeof(msg), sk) != OQS_SUCCESS) {
		fprintf(stderr, "Raccoon-G-44 sign failed\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}
	if (OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg), sig, sig_len, pk) != OQS_SUCCESS) {
		fprintf(stderr, "Raccoon-G-44 verify failed\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	if (OQS_SIG_hd_derive_pub(pk, chaincode, 7, pk_child) != OQS_SUCCESS ||
	        OQS_SIG_hd_derive_priv(sk, chaincode, 7, sk_child, pk_child_from_sk) != OQS_SUCCESS ||
	        OQS_MEM_secure_bcmp(pk_child, pk_child_from_sk, sizeof(pk_child)) != 0) {
		fprintf(stderr, "Raccoon-G-44 HD derivation failed\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	printf("Raccoon-G-44 example completed.\n");
#else
	printf("Raccoon-G-44 not enabled at compile-time.\n");
#endif

	OQS_destroy();
	return EXIT_SUCCESS;
}
