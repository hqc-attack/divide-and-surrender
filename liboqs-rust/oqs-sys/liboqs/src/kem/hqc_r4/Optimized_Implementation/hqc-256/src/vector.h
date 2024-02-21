#ifndef VECTOR_H
#define VECTOR_H

/**
 * @file vector.h
 * @brief Header file for vector.c
 */

#include "shake_prng.h"
#include <stdint.h>
#include <immintrin.h>

#define LOOP_SIZE CEIL_DIVIDE(PARAM_N, 256)

void HQC_R4_256_AVX2_vect_set_random_fixed_weight(seedexpander_state *ctx, __m256i *v256, uint16_t weight);
void HQC_R4_256_AVX2_vect_set_random(seedexpander_state *ctx, uint64_t *v);
void HQC_R4_256_AVX2_vect_set_random_from_prng(uint64_t *v, uint32_t size_v);

void HQC_R4_256_AVX2_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);
uint8_t HQC_R4_256_AVX2_vect_compare(const uint8_t *v1, const uint8_t *v2, uint32_t size);
void HQC_R4_256_AVX2_vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v);

void HQC_R4_256_AVX2_vect_print(const uint64_t *v, const uint32_t size);
void HQC_R4_256_AVX2_vect_print_sparse(const uint32_t *v, const uint16_t weight);

#endif
