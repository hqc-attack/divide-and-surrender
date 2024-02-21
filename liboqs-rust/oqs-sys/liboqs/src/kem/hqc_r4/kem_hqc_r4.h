// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_HQC_R4_H
#define OQS_KEM_HQC_R4_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_hqc_r4_128
#define OQS_KEM_hqc_r4_128_length_public_key 2249
#define OQS_KEM_hqc_r4_128_length_secret_key 2305
#define OQS_KEM_hqc_r4_128_length_ciphertext 4433
#define OQS_KEM_hqc_r4_128_length_shared_secret 64

OQS_KEM *OQS_KEM_hqc_r4_128_new(void);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_128_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_128_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_128_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e, const unsigned char *salt);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_128_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

OQS_API void OQS_KEM_hqc_r4_128_code_encode(uint8_t *em, const uint8_t *message);
OQS_API void OQS_KEM_hqc_r4_128_code_decode(uint8_t *m, const uint8_t *em);

OQS_API void OQS_KEM_hqc_r4_128_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
OQS_API void OQS_KEM_hqc_r4_128_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

OQS_API void OQS_KEM_hqc_r4_128_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk);
OQS_API void OQS_KEM_hqc_r4_128_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk);
OQS_API void OQS_KEM_hqc_r4_128_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

OQS_API void OQS_KEM_hqc_r4_128_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2);
OQS_API void OQS_KEM_hqc_r4_128_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);

OQS_API uint32_t OQS_KEM_hqc_r4_128_num_seedexpansions(const uint8_t *m);
OQS_API uint32_t OQS_KEM_hqc_r4_128_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);
OQS_API void OQS_KEM_hqc_r4_128_AVX2_shake_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen);
#endif

#ifdef OQS_ENABLE_KEM_hqc_r4_192
#define OQS_KEM_hqc_r4_192_length_public_key 4522
#define OQS_KEM_hqc_r4_192_length_secret_key 4586
#define OQS_KEM_hqc_r4_192_length_ciphertext 8978
#define OQS_KEM_hqc_r4_192_length_shared_secret 64
OQS_KEM *OQS_KEM_hqc_r4_192_new(void);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_192_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_192_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e, const unsigned char *salt);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_192_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

OQS_API void OQS_KEM_hqc_r4_192_code_encode(uint8_t *em, const uint8_t *message);
OQS_API void OQS_KEM_hqc_r4_192_code_decode(uint8_t *m, const uint8_t *em);

OQS_API void OQS_KEM_hqc_r4_192_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
OQS_API void OQS_KEM_hqc_r4_192_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

OQS_API void OQS_KEM_hqc_r4_192_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk);
OQS_API void OQS_KEM_hqc_r4_192_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk);
OQS_API void OQS_KEM_hqc_r4_192_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

OQS_API void OQS_KEM_hqc_r4_192_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2);
OQS_API void OQS_KEM_hqc_r4_192_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);

OQS_API uint32_t OQS_KEM_hqc_r4_192_num_seedexpansions(const uint8_t *m);
OQS_API uint32_t OQS_KEM_hqc_r4_192_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);
OQS_API void OQS_KEM_hqc_r4_192_AVX2_shake_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen);
#endif

#ifdef OQS_ENABLE_KEM_hqc_r4_256
#define OQS_KEM_hqc_r4_256_length_public_key 7245
#define OQS_KEM_hqc_r4_256_length_secret_key 7317
#define OQS_KEM_hqc_r4_256_length_ciphertext 14421
#define OQS_KEM_hqc_r4_256_length_shared_secret 64
OQS_KEM *OQS_KEM_hqc_r4_256_new(void);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_256_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_256_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_256_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e, const unsigned char *salt);
OQS_API OQS_STATUS OQS_KEM_hqc_r4_256_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

OQS_API void OQS_KEM_hqc_r4_256_code_encode(uint8_t *em, const uint8_t *message);
OQS_API void OQS_KEM_hqc_r4_256_code_decode(uint8_t *m, const uint8_t *em);

OQS_API void OQS_KEM_hqc_r4_256_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
OQS_API void OQS_KEM_hqc_r4_256_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

OQS_API void OQS_KEM_hqc_r4_256_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk);
OQS_API void OQS_KEM_hqc_r4_256_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk);
OQS_API void OQS_KEM_hqc_r4_256_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

OQS_API void OQS_KEM_hqc_r4_256_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2);
OQS_API void OQS_KEM_hqc_r4_256_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);

OQS_API uint32_t OQS_KEM_hqc_r4_256_num_seedexpansions(const uint8_t *m);
OQS_API uint32_t OQS_KEM_hqc_r4_256_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);
OQS_API void OQS_KEM_hqc_r4_256_AVX2_shake_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen);
#endif

#endif

