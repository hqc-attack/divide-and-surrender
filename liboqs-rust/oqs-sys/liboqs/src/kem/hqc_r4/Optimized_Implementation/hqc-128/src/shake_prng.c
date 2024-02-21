
/**
 * @file shake_prng.c
 * @brief Implementation of SHAKE-256 based PRNG and seedexpander
 */

#include "shake_prng.h"
#include <threads.h>

thread_local shake256incctx HQC_R4_128_AVX2_shake_prng_state;


/**
 * @brief SHAKE-256 with incremental API and domain separation
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[in] entropy_input Pointer to input entropy bytes
 * @param[in] personalization_string Pointer to the personalization string
 * @param[in] enlen Length of entropy string in bytes
 * @param[in] perlen Length of the personalization string in bytes
 */
void HQC_R4_128_AVX2_shake_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen) {
    uint8_t domain = PRNG_DOMAIN;
    HQC_R4_128_AVX2_shake256_inc_init(&HQC_R4_128_AVX2_shake_prng_state);
    HQC_R4_128_AVX2_shake256_inc_absorb(&HQC_R4_128_AVX2_shake_prng_state, entropy_input, enlen);
    HQC_R4_128_AVX2_shake256_inc_absorb(&HQC_R4_128_AVX2_shake_prng_state, personalization_string, perlen);
    HQC_R4_128_AVX2_shake256_inc_absorb(&HQC_R4_128_AVX2_shake_prng_state, &domain, 1);
    HQC_R4_128_AVX2_shake256_inc_finalize(&HQC_R4_128_AVX2_shake_prng_state);
}



/**
 * @brief A SHAKE-256 based PRNG
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[out] output Pointer to output
 * @param[in] outlen length of output in bytes
 */
void HQC_R4_128_AVX2_shake_prng(uint8_t *output, uint32_t outlen) {
    HQC_R4_128_AVX2_shake256_inc_squeeze(output, outlen, &HQC_R4_128_AVX2_shake_prng_state);
}



/**
 * @brief Initialiase a SHAKE-256 based seedexpander
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[out] state Keccak internal state and a counter
 * @param[in] seed A seed
 * @param[in] seedlen The seed bytes length
 */
void HQC_R4_128_AVX2_seedexpander_init(seedexpander_state *state, const uint8_t *seed, uint32_t seedlen) {
    uint8_t domain = SEEDEXPANDER_DOMAIN;
    HQC_R4_128_AVX2_shake256_inc_init(state);
    HQC_R4_128_AVX2_shake256_inc_absorb(state, seed, seedlen);
    HQC_R4_128_AVX2_shake256_inc_absorb(state, &domain, 1);
    HQC_R4_128_AVX2_shake256_inc_finalize(state);
}



/**
 * @brief A SHAKE-256 based seedexpander
 *
 * Derived from function SHAKE_256 in fips202.c
 * Squeezes Keccak state by 64-bit blocks (hardware version compatibility)
 *
 * @param[out] state Internal state of SHAKE
 * @param[out] output The XOF data
 * @param[in] outlen Number of bytes to return
 */
void HQC_R4_128_AVX2_seedexpander(seedexpander_state *state, uint8_t *output, uint32_t outlen) {
    const uint8_t bsize = sizeof(uint64_t);
    const uint8_t remainder = outlen % bsize;
    uint8_t tmp[sizeof(uint64_t)];
    HQC_R4_128_AVX2_shake256_inc_squeeze(output, outlen - remainder, state);
    if (remainder != 0) {
      HQC_R4_128_AVX2_shake256_inc_squeeze(tmp, bsize, state);
      output += outlen - remainder;
      for (uint8_t i = 0; i < remainder; i++){
        output[i] = tmp[i];
      }
    }
}
