#ifndef CODE_H
#define CODE_H

/**
 * @file code.h
 * @brief Header file of code.c
 */

#include "parameters.h"
#include <stddef.h>
#include <stdint.h>

void HQC_R4_256_AVX2_code_encode(uint64_t *codeword, const uint64_t *message);
void HQC_R4_256_AVX2_code_decode(uint64_t *message, const uint64_t *vector);

#endif
