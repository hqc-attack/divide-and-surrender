/**
 * @file kem.c
 * @brief Implementation of api.h
 */

#include "api.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "shake_ds.h"
#include "fips202.h"
#include "vector.h"
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#ifdef VERBOSE
#include <stdio.h>
#endif


/**
 * @brief Keygen of the HQC_KEM IND_CAA2 scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used to generate the vector <b>h</b>.
 *
 * The secret key is composed of the seed used to generate vectors <b>x</b> and <b>y</b>.
 * As a technicality, the public key is appended to the secret key in order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 * @returns 0 if keygen is successful
 */
int HQC_R4_192_AVX2_crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    #ifdef VERBOSE
        printf("\n\n\n\n### KEYGEN ###");
    #endif

    HQC_R4_192_AVX2_hqc_pke_keygen(pk, sk);
    return 0;
}



/**
 * @brief Encapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ct String containing the ciphertext
 * @param[out] ss String containing the shared secret
 * @param[in] pk String containing the public key
 * @returns 0 if encapsulation is successful
 */
int HQC_R4_192_AVX2_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    #ifdef VERBOSE
        printf("\n\n\n\n### ENCAPS ###");
    #endif

    uint8_t theta[SHAKE256_512_BYTES] = {0};
    uint8_t m[VEC_K_SIZE_BYTES] = {0};
    uint64_t u[VEC_N_256_SIZE_64] = {0};
    uint64_t v[VEC_N1N2_256_SIZE_64] = {0};
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES] = {0};
    uint64_t salt[SALT_SIZE_64] = {0};
    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES] = {0};
    shake256incctx shake256state;

    // Computing m
    HQC_R4_192_AVX2_vect_set_random_from_prng((uint64_t *)m, VEC_K_SIZE_64);

    // Computing theta
    HQC_R4_192_AVX2_vect_set_random_from_prng(salt, SALT_SIZE_64);
    memcpy(tmp, m, VEC_K_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES, salt, SALT_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m
    HQC_R4_192_AVX2_hqc_pke_encrypt(u, v, (uint64_t *)m, theta, pk);

    // Computing shared secret
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES, u, VEC_N_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, ss, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    // Computing ciphertext
    HQC_R4_192_AVX2_hqc_ciphertext_to_string(ct, u, v, salt);

    #ifdef VERBOSE
        printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
        printf("\n\nm: "); HQC_R4_192_AVX2_vect_print((uint64_t *)m, VEC_K_SIZE_BYTES);
        printf("\n\ntheta: "); for(int i = 0 ; i < SHAKE256_512_BYTES ; ++i) printf("%02x", theta[i]);
        printf("\n\nciphertext: "); for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) printf("%02x", ct[i]);
        printf("\n\nsecret 1: "); for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%02x", ss[i]);
    #endif

    return 0;
}



/**
 * @brief Decapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ss String containing the shared secret
 * @param[in] ct String containing the cipĥertext
 * @param[in] sk String containing the secret key
 * @returns 0 if decapsulation is successful, -1 otherwise
 */
int HQC_R4_192_AVX2_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    #ifdef VERBOSE
        printf("\n\n\n\n### DECAPS ###");
    #endif

    uint8_t result;
    __m256i u_256[VEC_N_256_SIZE_64 >> 2] = {0};
    uint64_t v[VEC_N1N2_256_SIZE_64] = {0};
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    uint8_t m[VEC_K_SIZE_BYTES] = {0};
    uint8_t sigma[VEC_K_SIZE_BYTES] = {0};
    uint8_t theta[SHAKE256_512_BYTES] = {0};
    uint64_t u2[VEC_N_256_SIZE_64] = {0};
    uint64_t v2[VEC_N1N2_256_SIZE_64] = {0};
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES] = {0};
    uint64_t salt[SALT_SIZE_64] = {0};
    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES] = {0};
    shake256incctx shake256state;

    // Retrieving u, v and d from ciphertext
    HQC_R4_192_AVX2_hqc_ciphertext_from_string((uint64_t *) u_256, v, salt, ct);

    // Retrieving pk from sk
    memcpy(pk, sk + SEED_BYTES + VEC_K_SIZE_BYTES, PUBLIC_KEY_BYTES);

    // Decrypting
    result = HQC_R4_192_AVX2_hqc_pke_decrypt((uint64_t *)m, sigma, u_256, v, sk);

    // Computing theta
    memcpy(tmp, m, VEC_K_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES, salt, SALT_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m'
    HQC_R4_192_AVX2_hqc_pke_encrypt(u2, v2, (uint64_t *)m, theta, pk);

    // Check if c != c'
    result |= HQC_R4_192_AVX2_vect_compare((uint8_t *) u_256, (uint8_t *) u2, VEC_N_SIZE_BYTES);
    result |= HQC_R4_192_AVX2_vect_compare((uint8_t *) v, (uint8_t *) v2, VEC_N1N2_SIZE_BYTES);

    result = (uint8_t) (-((int16_t) result) >> 15);
    
    for (size_t i = 0; i < VEC_K_SIZE_BYTES; ++i) {
        mc[i] = (m[i] & result) ^ (sigma[i] & ~result);
    }

    // Computing shared secret
    memcpy(mc + VEC_K_SIZE_BYTES, u_256, VEC_N_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, ss, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    #ifdef VERBOSE
        printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
        printf("\n\nsk: "); for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) printf("%02x", sk[i]);
        printf("\n\nciphertext: "); for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) printf("%02x", ct[i]);
        printf("\n\nm: "); HQC_R4_192_AVX2_vect_print((uint64_t *)m, VEC_K_SIZE_BYTES);
        printf("\n\ntheta: "); for(int i = 0 ; i < SHAKE256_512_BYTES ; ++i) printf("%02x", theta[i]);
        printf("\n\n\n# Checking Ciphertext- Begin #");
        printf("\n\nu2: "); HQC_R4_192_AVX2_vect_print(u2, VEC_N_SIZE_BYTES);
        printf("\n\nv2: "); HQC_R4_192_AVX2_vect_print(v2, VEC_N1N2_SIZE_BYTES);
        printf("\n\n# Checking Ciphertext - End #\n");
    #endif

    return -(~result & 1);
}

int HQC_R4_192_AVX2_crypto_kem_enc_chosen_inputs(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *m, const unsigned char *u, const unsigned char *r2, const unsigned char *e, const unsigned char *salt) {
    #ifdef VERBOSE
        printf("\n\n\n\n### ENCAPS ###");
    #endif

    uint8_t theta[SHAKE256_512_BYTES] = {0};
    uint64_t v[VEC_N1N2_256_SIZE_64] = {0};
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES] = {0};
    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES] = {0};
    shake256incctx shake256state;

    // Computing m
    // HQC_R4_192_AVX2_vect_set_random_from_prng((uint64_t *)m, VEC_K_SIZE_64);

    // Computing theta
    // HQC_R4_192_AVX2_vect_set_random_from_prng(salt, SALT_SIZE_64);
    memcpy(tmp, m, VEC_K_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES, salt, SALT_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m
    HQC_R4_192_AVX2_hqc_pke_encrypt_chosen_inputs(u, v, (uint64_t *)m, theta, pk, r2, e);

    // Computing shared secret
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES, u, VEC_N_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, ss, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    // Computing ciphertext
    HQC_R4_192_AVX2_hqc_ciphertext_to_string(ct, u, v, salt);

    #ifdef VERBOSE
        printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
        printf("\n\nm: "); vect_print((uint64_t *)m, VEC_K_SIZE_BYTES);
        printf("\n\ntheta: "); for(int i = 0 ; i < SHAKE256_512_BYTES ; ++i) printf("%02x", theta[i]);
        printf("\n\nciphertext: "); for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) printf("%02x", ct[i]);
        printf("\n\nsecret 1: "); for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%02x", ss[i]);
    #endif

    return 0;
}

uint32_t HQC_R4_192_AVX2_division_latency(const uint8_t *m, const uint8_t *pk, const uint8_t *salt) {
    __m256i h_256[VEC_N_256_SIZE_64 >> 2];
    __m256i s_256[VEC_N_256_SIZE_64 >> 2];

#ifdef __STDC_LIB_EXT1__
    memset_s(h_256, 0, (VEC_N_256_SIZE_64 >> 2) * sizeof(__m256i));
    memset_s(s_256, 0, (VEC_N_256_SIZE_64 >> 2) * sizeof(__m256i));
#else
    memset(h_256, 0, (VEC_N_256_SIZE_64 >> 2) * sizeof(__m256i));
    memset(s_256, 0, (VEC_N_256_SIZE_64 >> 2) * sizeof(__m256i));
#endif

    // Retrieve h and s from public key
    HQC_R4_192_AVX2_hqc_public_key_from_string((uint64_t *)h_256, (uint64_t *)s_256, pk);
    uint8_t theta[SHAKE256_512_BYTES] = {0};
    // vect_set_random_from_prng(salt, SALT_SIZE_64);

    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES] = {0};
    shake256incctx shake256state;
    memcpy(tmp, m, VEC_K_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES, salt, SALT_SIZE_BYTES);
    HQC_R4_192_AVX2_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);
    seedexpander_state ctx;
    // Create seed_expander from theta
    HQC_R4_192_AVX2_seedexpander_init(&ctx, theta, SEED_BYTES);

    // Retrieve h and s from public key

    // Generate r1, r2 and e
    uint64_t total_latency_zen_2 = 0;
    for (int j = 0; j < 3; ++j) {
        uint32_t weight = PARAM_OMEGA_R;
        if (j == 2) {
            weight = PARAM_OMEGA_E;
        }
        uint32_t rand_u32[PARAM_OMEGA_R] = {0};
        HQC_R4_192_AVX2_seedexpander(&ctx, (uint8_t *)&rand_u32, 4 * weight);
        for (uint32_t k = 0; k < weight; ++k) {
            uint32_t result = rand_u32[k];  // / (PARAM_N - k);
            uint32_t result_bits = 0;
            if (result != 0) {
                result_bits = 32 - __builtin_clz(result);
            }
            total_latency_zen_2 += 8 + (result_bits + 1) / 2;
        }
    }
    return total_latency_zen_2;
}
