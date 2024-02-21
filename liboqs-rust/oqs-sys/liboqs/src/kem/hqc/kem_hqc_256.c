// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_hqc.h>

#if defined(OQS_ENABLE_KEM_hqc_256)

OQS_KEM *OQS_KEM_hqc_256_new(void) {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_hqc_256;
	kem->alg_version = "hqc-submission_2020-10-01 via https://github.com/jschanck/package-pqclean/tree/29f79e72/hqc";

	kem->claimed_nist_level = 5;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_hqc_256_length_public_key;
	kem->length_secret_key = OQS_KEM_hqc_256_length_secret_key;
	kem->length_ciphertext = OQS_KEM_hqc_256_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_hqc_256_length_shared_secret;

	kem->keypair = OQS_KEM_hqc_256_keypair;
	kem->encaps = OQS_KEM_hqc_256_encaps;
	kem->decaps = OQS_KEM_hqc_256_decaps;

	return kem;
}

extern int PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(OQS_ENABLE_KEM_hqc_256_avx2)
extern int PQCLEAN_HQCRMRS256_AVX2_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQCRMRS256_AVX2_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQCRMRS256_AVX2_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

OQS_API OQS_STATUS OQS_KEM_hqc_256_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_hqc_256_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1) && OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_HQCRMRS256_AVX2_crypto_kem_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_hqc_256_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_hqc_256_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1) && OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_HQCRMRS256_AVX2_crypto_kem_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_hqc_256_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_hqc_256_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1) && OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_HQCRMRS256_AVX2_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#endif
}

#include <code.h>
#include <reed_muller.h>

void OQS_KEM_hqc_256_code_encode(uint8_t *em, const uint8_t *message) {
	PQCLEAN_HQCRMRS256_AVX2_code_encode(em, message);
}

void OQS_KEM_hqc_256_code_decode(uint8_t *m, const uint8_t *em) {
	PQCLEAN_HQCRMRS256_AVX2_code_decode(m, em);
}

void OQS_KEM_hqc_256_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg) {
	PQCLEAN_HQCRMRS256_AVX2_reed_muller_encode_single(cdw, msg);
}

void OQS_KEM_hqc_256_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw) {
	PQCLEAN_HQCRMRS256_AVX2_reed_muller_decode_single(msg, cdw);
}


OQS_STATUS OQS_KEM_hqc_256_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *r1, const unsigned char *r2, unsigned const char *e) {
	return PQCLEAN_HQCRMRS256_AVX2_crypto_kem_enc_chosen_inputs(ciphertext, shared_secret, public_key, m, r1, r2, e);
}


void OQS_KEM_hqc_256_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk) {
	PQCLEAN_HQCRMRS256_AVX2_hqc_public_key_from_string(h, s, pk);
}

void OQS_KEM_hqc_256_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk) {
	PQCLEAN_HQCRMRS256_AVX2_hqc_secret_key_from_string(x, y, pk, sk);
}

OQS_API void OQS_KEM_hqc_256_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct) {
	PQCLEAN_HQCRMRS256_AVX2_hqc_ciphertext_from_string(u, v, d, ct);
}

#include <vector.h>
#include <gf2x.h>

void OQS_KEM_hqc_256_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2) {
	PQCLEAN_HQCRMRS256_AVX2_vect_mul(o, a1, a2);
}

void OQS_KEM_hqc_256_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size) {
	PQCLEAN_HQCRMRS256_AVX2_vect_add(o, v1, v2, size);
}

OQS_API uint32_t OQS_KEM_hqc_256_num_seedexpansions(const uint8_t *m) {
	return PQCLEAN_HQCRMRS256_AVX2_hqc_num_seedexpansions(m);
}

OQS_API uint32_t OQS_KEM_hqc_256_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt) {
	return 0;
}

#endif
