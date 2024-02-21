/**
 * @file api.h
 * @brief NIST KEM API used by the HQC_KEM IND-CCA2 scheme
 */

#ifndef API_H
#define API_H

#include <stdint.h>

#define CRYPTO_ALGNAME                      "HQC-192"

#define CRYPTO_SECRETKEYBYTES               4586
#define CRYPTO_PUBLICKEYBYTES               4522
#define CRYPTO_BYTES                        64
#define CRYPTO_CIPHERTEXTBYTES              8978

// As a technicality, the public key is appended to the secret key in order to respect the NIST API.
// Without this constraint, CRYPTO_SECRETKEYBYTES would be defined as 32

int HQC_R4_192_AVX2_crypto_kem_keypair(unsigned char* pk, unsigned char* sk);
int HQC_R4_192_AVX2_crypto_kem_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
int HQC_R4_192_AVX2_crypto_kem_enc_chosen_inputs(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e, const unsigned char *salt);
int HQC_R4_192_AVX2_crypto_kem_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);
uint32_t HQC_R4_192_AVX2_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt);

#endif
