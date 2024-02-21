// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_HQC_H
#define OQS_KEM_HQC_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_hqc_128
#define OQS_KEM_hqc_128_length_public_key 2249
#define OQS_KEM_hqc_128_length_secret_key 2289
#define OQS_KEM_hqc_128_length_ciphertext 4481
#define OQS_KEM_hqc_128_length_shared_secret 64

OQS_KEM *OQS_KEM_hqc_128_new(void);
OQS_API OQS_STATUS OQS_KEM_hqc_128_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_hqc_128_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_hqc_128_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e);
OQS_API OQS_STATUS OQS_KEM_hqc_128_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

OQS_API void OQS_KEM_hqc_128_code_encode(uint8_t *em, const uint8_t *message);
OQS_API void OQS_KEM_hqc_128_code_decode(uint8_t *m, const uint8_t *em);

OQS_API void OQS_KEM_hqc_128_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
OQS_API void OQS_KEM_hqc_128_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

OQS_API void OQS_KEM_hqc_128_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk);
OQS_API void OQS_KEM_hqc_128_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk);
OQS_API void OQS_KEM_hqc_128_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

OQS_API void OQS_KEM_hqc_128_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2);
OQS_API void OQS_KEM_hqc_128_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);

OQS_API uint32_t OQS_KEM_hqc_128_num_seedexpansions(const uint8_t *m);
OQS_API uint32_t OQS_KEM_hqc_128_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);
#endif

#ifdef OQS_ENABLE_KEM_hqc_192
#define OQS_KEM_hqc_192_length_public_key 4522
#define OQS_KEM_hqc_192_length_secret_key 4562
#define OQS_KEM_hqc_192_length_ciphertext 9026
#define OQS_KEM_hqc_192_length_shared_secret 64
OQS_KEM *OQS_KEM_hqc_192_new(void);
OQS_API OQS_STATUS OQS_KEM_hqc_192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_hqc_192_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_hqc_192_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e);
OQS_API OQS_STATUS OQS_KEM_hqc_192_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

OQS_API void OQS_KEM_hqc_192_code_encode(uint8_t *em, const uint8_t *message);
OQS_API void OQS_KEM_hqc_192_code_decode(uint8_t *m, const uint8_t *em);

OQS_API void OQS_KEM_hqc_192_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
OQS_API void OQS_KEM_hqc_192_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

OQS_API void OQS_KEM_hqc_192_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk);
OQS_API void OQS_KEM_hqc_192_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk);
OQS_API void OQS_KEM_hqc_192_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

OQS_API void OQS_KEM_hqc_192_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2);
OQS_API void OQS_KEM_hqc_192_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);

OQS_API uint32_t OQS_KEM_hqc_192_num_seedexpansions(const uint8_t *m);
OQS_API uint32_t OQS_KEM_hqc_192_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);
#endif

#ifdef OQS_ENABLE_KEM_hqc_256
#define OQS_KEM_hqc_256_length_public_key 7245
#define OQS_KEM_hqc_256_length_secret_key 7285
#define OQS_KEM_hqc_256_length_ciphertext 14469
#define OQS_KEM_hqc_256_length_shared_secret 64
OQS_KEM *OQS_KEM_hqc_256_new(void);
OQS_API OQS_STATUS OQS_KEM_hqc_256_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_hqc_256_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_hqc_256_encaps_chosen_inputs(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e);
OQS_API OQS_STATUS OQS_KEM_hqc_256_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

OQS_API void OQS_KEM_hqc_256_code_encode(uint8_t *em, const uint8_t *message);
OQS_API void OQS_KEM_hqc_256_code_decode(uint8_t *m, const uint8_t *em);

OQS_API void OQS_KEM_hqc_256_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
OQS_API void OQS_KEM_hqc_256_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

OQS_API void OQS_KEM_hqc_256_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk);
OQS_API void OQS_KEM_hqc_256_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *pk, const uint8_t *sk);
OQS_API void OQS_KEM_hqc_256_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

OQS_API void OQS_KEM_hqc_256_vect_mul(uint64_t *o, const uint8_t *a1, const uint8_t *a2);
OQS_API void OQS_KEM_hqc_256_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);

OQS_API uint32_t OQS_KEM_hqc_256_num_seedexpansions(const uint8_t *m);
OQS_API uint32_t OQS_KEM_hqc_256_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);
#endif

#endif

