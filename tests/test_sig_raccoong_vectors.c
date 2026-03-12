// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>
#include <oqs/sha2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OQS_ENABLE_SIG_raccoon_g_44
static int check(int ok, const char *msg) {
	if (!ok) {
		fprintf(stderr, "%s\n", msg);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
static int check_sha256_matches_expected(const uint8_t *buf, size_t len, const uint8_t expected[32], const char *msg) {
	uint8_t digest[32];
	OQS_SHA2_sha256(digest, buf, len);
	return check(OQS_MEM_secure_bcmp(digest, expected, sizeof(digest)) == 0, msg);
}
#endif

int main(void) {
	OQS_init();

#ifndef OQS_ENABLE_SIG_raccoon_g_44
	printf("Raccoon-G-44 not enabled at compile-time.\n");
	OQS_destroy();
	return EXIT_SUCCESS;
#else
	const uint8_t test_vector_seed[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	const uint8_t chaincode[OQS_SIG_raccoon_g_44_length_chaincode] = {0};
	const uint8_t msg[] = "test message";

	/* SHA-256 anchors from tests/KATs/sig/raccoong/reference_kat_p11.json */
	const uint8_t expected_pk_sha256[32] = {
		0x79, 0x3c, 0x60, 0xca, 0x7c, 0xfd, 0x7f, 0x96,
		0xf7, 0x98, 0xa3, 0x41, 0x8b, 0xa7, 0x93, 0xcf,
		0x6b, 0x6f, 0x47, 0xd7, 0x6a, 0xa3, 0xb3, 0x7b,
		0x59, 0x2d, 0xb0, 0x3c, 0x4d, 0x7e, 0x82, 0xe1
	};
	const uint8_t expected_sk_sha256[32] = {
		0x4e, 0x11, 0x4d, 0x70, 0x87, 0x23, 0xd5, 0x35,
		0x90, 0xe7, 0x6c, 0xc4, 0x78, 0xa7, 0x84, 0xb1,
		0x59, 0x04, 0xc7, 0x7a, 0x78, 0x12, 0xc4, 0x46,
		0x5f, 0x3b, 0xaa, 0x41, 0xd9, 0x1d, 0x83, 0xfe
	};
	const uint8_t expected_pk_child_sha256[32] = {
		0xf9, 0x49, 0x63, 0xdc, 0xd1, 0xce, 0xc6, 0xe8,
		0x74, 0x0c, 0xd4, 0x79, 0xf1, 0x20, 0xf3, 0xcb,
		0x94, 0x0e, 0x8a, 0x26, 0x84, 0xcf, 0x80, 0xfe,
		0x75, 0xe9, 0xb2, 0xc5, 0x74, 0xe8, 0x14, 0x24
	};
	const uint8_t expected_sk_child_sha256[32] = {
		0x0f, 0x35, 0x49, 0x0b, 0x3e, 0xf2, 0x85, 0x22,
		0xb6, 0x07, 0x46, 0xba, 0x95, 0x82, 0x03, 0xdb,
		0xdf, 0xff, 0x96, 0x02, 0x4d, 0x8d, 0x0c, 0x29,
		0x27, 0x64, 0xbb, 0xd0, 0x9a, 0xa5, 0x43, 0x1e
	};

	uint8_t pk[OQS_SIG_raccoon_g_44_length_public_key];
	uint8_t sk[OQS_SIG_raccoon_g_44_length_secret_key];
	uint8_t pk_child_pub[OQS_SIG_raccoon_g_44_length_public_key];
	uint8_t pk_child_priv[OQS_SIG_raccoon_g_44_length_public_key];
	uint8_t sk_child[OQS_SIG_raccoon_g_44_length_secret_key];
	uint8_t sig_master[OQS_SIG_raccoon_g_44_length_signature];
	uint8_t sig_master_2[OQS_SIG_raccoon_g_44_length_signature];
	uint8_t sig_child[OQS_SIG_raccoon_g_44_length_signature];
	size_t sig_master_len = 0, sig_master_len_2 = 0, sig_child_len = 0;

	if (check(OQS_SIG_raccoon_g_44_keypair_det(pk, sk, test_vector_seed, sizeof(test_vector_seed)) == OQS_SUCCESS,
	          "Raccoon-G-44 deterministic keypair generation vector failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check_sha256_matches_expected(pk, sizeof(pk), expected_pk_sha256, "DetKeyGen vector drift: PK SHA-256 mismatch") != EXIT_SUCCESS) {
		goto err;
	}
	if (check_sha256_matches_expected(sk, sizeof(sk), expected_sk_sha256, "DetKeyGen vector drift: SK SHA-256 mismatch") != EXIT_SUCCESS) {
		goto err;
	}

	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_raccoon_g_44);
	if (check(sig != NULL, "OQS_SIG_new(Raccoon-G-44) failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check(sig->length_public_key == OQS_SIG_raccoon_g_44_length_public_key &&
	          sig->length_public_key == 16144,
	          "Binary compatibility failure: public key size changed") != EXIT_SUCCESS) {
		OQS_SIG_free(sig);
		goto err;
	}
	if (check(sig->length_secret_key == OQS_SIG_raccoon_g_44_length_secret_key &&
	          sig->length_secret_key == 32272,
	          "Binary compatibility failure: secret key size changed") != EXIT_SUCCESS) {
		OQS_SIG_free(sig);
		goto err;
	}
	if (check(sig->length_signature == OQS_SIG_raccoon_g_44_length_signature &&
	          sig->length_signature == 20768,
	          "Binary compatibility failure: signature size changed") != EXIT_SUCCESS) {
		OQS_SIG_free(sig);
		goto err;
	}
	OQS_SIG_free(sig);

	if (check(OQS_SIG_hd_derive_pub(pk, chaincode, 0, pk_child_pub) == OQS_SUCCESS,
	          "CKDer_pub vector failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check(OQS_SIG_hd_derive_priv(sk, chaincode, 0, sk_child, pk_child_priv) == OQS_SUCCESS,
	          "CKDer_priv vector failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check_sha256_matches_expected(pk_child_pub, sizeof(pk_child_pub), expected_pk_child_sha256, "CKDer vector drift: child PK SHA-256 mismatch") != EXIT_SUCCESS) {
		goto err;
	}
	if (check_sha256_matches_expected(sk_child, sizeof(sk_child), expected_sk_child_sha256, "CKDer vector drift: child SK SHA-256 mismatch") != EXIT_SUCCESS) {
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
	if (check(OQS_SIG_raccoon_g_44_sign(sig_master_2, &sig_master_len_2, msg, sizeof(msg) - 1, sk) == OQS_SUCCESS,
	          "Second master signature generation failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_master, sig_master_len, pk) == OQS_SUCCESS,
	          "Master signature verification failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check(OQS_SIG_raccoon_g_44_verify(msg, sizeof(msg) - 1, sig_master_2, sig_master_len_2, pk) == OQS_SUCCESS,
	          "Second master signature verification failed") != EXIT_SUCCESS) {
		goto err;
	}
	if (check(sig_master_len == OQS_SIG_raccoon_g_44_length_signature &&
	          sig_master_len_2 == OQS_SIG_raccoon_g_44_length_signature,
	          "Master signatures must use fixed ABI length") != EXIT_SUCCESS) {
		goto err;
	}
	if (check(OQS_MEM_secure_bcmp(sig_master, sig_master_2, OQS_SIG_raccoon_g_44_length_signature) != 0,
	          "Randomized signing failure: two signatures for same key/message are identical") != EXIT_SUCCESS) {
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
	if (check(sig_child_len == OQS_SIG_raccoon_g_44_length_signature,
	          "Child signature must use fixed ABI length") != EXIT_SUCCESS) {
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
