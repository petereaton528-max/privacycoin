/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 petereaton528-max */
#include "jh.h"
#define SPH_UNALIGNED 0
#include "pc_sphlib/jh_sph.c"
#include <stdint.h>
#define JH_CASE(N) case N: sph_jh##N##_init(&ctx); \
    if (bytes) sph_jh##N(&ctx, input, bytes); \
    sph_jh##N##_addbits_and_close(&ctx, tail, remainder, output); break
HashReturn jh_hash(int bits, const BitSequence *input, DataLength length_bits,
                   BitSequence *output) {
    sph_jh_context ctx;
    if (bits != 224 && bits != 256 && bits != 384 && bits != 512)
        return BAD_HASHLEN;
    if (length_bits / 8 > SIZE_MAX) return FAIL;
    size_t bytes = (size_t)(length_bits / 8);
    unsigned remainder = (unsigned)(length_bits % 8);
    unsigned tail = remainder ? input[bytes] : 0;
    switch (bits) { JH_CASE(224); JH_CASE(256); JH_CASE(384); JH_CASE(512); }
    return SUCCESS;
}
