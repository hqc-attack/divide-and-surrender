
/**
 * @file shake_ds.c
 * @brief Implementation SHAKE-256 with incremental API and domain separation
 */

#include "shake_ds.h"


/**
 * @brief SHAKE-256 with incremental API and domain separation
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[out] state Internal state of SHAKE
 * @param[in] output Pointer to output
 * @param[in] input Pointer to input
 * @param[in] inlen length of input in bytes
 * @param[in] domain byte for domain separation
 */
void HQC_R4_192_AVX2_shake256_512_ds(shake256incctx *state, uint8_t *output, const uint8_t *input, size_t inlen, uint8_t domain) {
    /* Init state */
    HQC_R4_192_AVX2_shake256_inc_init(state);

    /* Absorb input */
    HQC_R4_192_AVX2_shake256_inc_absorb(state, input, inlen);

    /* Absorb domain separation byte */
    HQC_R4_192_AVX2_shake256_inc_absorb(state, &domain, 1);

    /* Finalize */
    HQC_R4_192_AVX2_shake256_inc_finalize(state);

    /* Squeeze output */
    HQC_R4_192_AVX2_shake256_inc_squeeze(output, 512/8, state);
}
