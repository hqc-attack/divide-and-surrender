#ifndef REED_MULLER_H
#define REED_MULLER_H

/**
 * @file reed_muller.h
 * @brief Header file of reed_muller.c
 */

#include "parameters.h"
#include <stddef.h>
#include <stdint.h>

void HQC_R4_192_AVX2_reed_muller_encode(uint64_t* cdw, const uint64_t* msg);
void HQC_R4_192_AVX2_reed_muller_decode(uint64_t* msg, const uint64_t* cdw);

void HQC_R4_192_AVX2_reed_muller_encode_single(uint8_t *cdw, const uint8_t *msg);
void HQC_R4_192_AVX2_reed_muller_decode_single(uint8_t *msg, const uint8_t *cdw);

#endif
