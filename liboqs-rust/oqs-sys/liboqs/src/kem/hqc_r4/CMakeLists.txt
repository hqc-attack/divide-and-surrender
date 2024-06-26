# SPDX-License-Identifier: MIT

# This file was generated by
# scripts/copy_from_upstream/copy_from_upstream.py

set(_HQC_R4_OBJS "")

if(OQS_ENABLE_KEM_hqc_r4_128_avx2)
    add_library(hqc_r4_128_avx2 STATIC kem_hqc_r4_128.c Optimized_Implementation/hqc-128/src/code.c Optimized_Implementation/hqc-128/src/fft.c Optimized_Implementation/hqc-128/src/gf2x.c Optimized_Implementation/hqc-128/src/gf.c Optimized_Implementation/hqc-128/src/hqc.c Optimized_Implementation/hqc-128/src/kem.c Optimized_Implementation/hqc-128/src/parsing.c Optimized_Implementation/hqc-128/src/reed_muller.c Optimized_Implementation/hqc-128/src/reed_solomon.c Optimized_Implementation/hqc-128/src/shake_ds.c Optimized_Implementation/hqc-128/src/shake_prng.c Optimized_Implementation/hqc-128/src/vector.c Optimized_Implementation/hqc-128/lib/fips202/fips202.c)
    target_include_directories(hqc_r4_128_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/Optimized_Implementation/hqc-128/src ${CMAKE_CURRENT_LIST_DIR}/Optimized_Implementation/hqc-128/lib/fips202)
    target_include_directories(hqc_r4_128_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(hqc_r4_128_avx2 PRIVATE -O3 -std=c99 -funroll-all-loops -ffat-lto-objects -mavx -mavx2 -mbmi -mpclmul -pedantic -Wall -Wextra)
    # target_compile_options(hqc_r4_128_avx2 PRIVATE  -mavx2  -mbmi  -mpclmul )
    target_compile_options(hqc_r4_128_avx2 PRIVATE -Wno-missing-braces)
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(hqc_r4_128_avx2 PRIVATE old_gas_syntax)
    endif()
    set(_HQC_R4_OBJS ${_HQC_R4_OBJS} $<TARGET_OBJECTS:hqc_r4_128_avx2>)
endif()

if(OQS_ENABLE_KEM_hqc_r4_192_avx2)
    add_library(hqc_r4_192_avx2 STATIC kem_hqc_r4_192.c Optimized_Implementation/hqc-192/src/code.c Optimized_Implementation/hqc-192/src/fft.c Optimized_Implementation/hqc-192/src/gf2x.c Optimized_Implementation/hqc-192/src/gf.c Optimized_Implementation/hqc-192/src/hqc.c Optimized_Implementation/hqc-192/src/kem.c Optimized_Implementation/hqc-192/src/parsing.c Optimized_Implementation/hqc-192/src/reed_muller.c Optimized_Implementation/hqc-192/src/reed_solomon.c Optimized_Implementation/hqc-192/src/shake_ds.c Optimized_Implementation/hqc-192/src/shake_prng.c Optimized_Implementation/hqc-192/src/vector.c Optimized_Implementation/hqc-192/lib/fips202/fips202.c)
    target_include_directories(hqc_r4_192_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/Optimized_Implementation/hqc-192/src ${CMAKE_CURRENT_LIST_DIR}/Optimized_Implementation/hqc-192/lib/fips202)
    target_include_directories(hqc_r4_192_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(hqc_r4_192_avx2 PRIVATE -O3 -std=c99 -funroll-all-loops -ffat-lto-objects -mavx -mavx2 -mbmi -mpclmul -pedantic -Wall -Wextra)
    # target_compile_options(hqc_r4_192_avx2 PRIVATE  -mavx2  -mbmi  -mpclmul )
    target_compile_options(hqc_r4_192_avx2 PRIVATE -Wno-missing-braces)
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(hqc_r4_192_avx2 PRIVATE old_gas_syntax)
    endif()
    set(_HQC_R4_OBJS ${_HQC_R4_OBJS} $<TARGET_OBJECTS:hqc_r4_192_avx2>)
endif()

if(OQS_ENABLE_KEM_hqc_r4_256_avx2)
    add_library(hqc_r4_256_avx2 STATIC kem_hqc_r4_256.c Optimized_Implementation/hqc-256/src/code.c Optimized_Implementation/hqc-256/src/fft.c Optimized_Implementation/hqc-256/src/gf2x.c Optimized_Implementation/hqc-256/src/gf.c Optimized_Implementation/hqc-256/src/hqc.c Optimized_Implementation/hqc-256/src/kem.c Optimized_Implementation/hqc-256/src/parsing.c Optimized_Implementation/hqc-256/src/reed_muller.c Optimized_Implementation/hqc-256/src/reed_solomon.c Optimized_Implementation/hqc-256/src/shake_ds.c Optimized_Implementation/hqc-256/src/shake_prng.c Optimized_Implementation/hqc-256/src/vector.c Optimized_Implementation/hqc-256/lib/fips202/fips202.c)
    target_include_directories(hqc_r4_256_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/Optimized_Implementation/hqc-256/src ${CMAKE_CURRENT_LIST_DIR}/Optimized_Implementation/hqc-256/lib/fips202)
    target_include_directories(hqc_r4_256_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(hqc_r4_256_avx2 PRIVATE -O3 -std=c99 -funroll-all-loops -ffat-lto-objects -mavx -mavx2 -mbmi -mpclmul -pedantic -Wall -Wextra)
    # target_compile_options(hqc_r4_256_avx2 PRIVATE  -mavx2  -mbmi  -mpclmul )
    target_compile_options(hqc_r4_256_avx2 PRIVATE -Wno-missing-braces)
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(hqc_r4_256_avx2 PRIVATE old_gas_syntax)
    endif()
    set(_HQC_R4_OBJS ${_HQC_R4_OBJS} $<TARGET_OBJECTS:hqc_r4_256_avx2>)
endif()

set(HQC_R4_OBJS ${_HQC_R4_OBJS} PARENT_SCOPE)
