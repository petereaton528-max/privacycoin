/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 petereaton528-max
 * Adapter to the separately licensed, unmodified sphlib permutation.
 * Legacy Keccak suffix 0x01; never FIPS SHA3's 0x06.
 * Internal lane complementation follows sphlib's documented close routine. */
#include <stdlib.h>
#include <string.h>
#define SPH_UNALIGNED 0
#define SPH_KECCAK_64 1
#define SPH_KECCAK_NOCOPY 1
#define SPH_KECCAK_UNROLL 1
#define keccak_init pc_sphlib_internal_init
#include "../vendor/keccak_sph.c"
#undef keccak_init
#include "keccak.h"

static int complemented(unsigned i) {
    return i == 1 || i == 2 || i == 8 || i == 12 || i == 17 || i == 20;
}
static void export_state(const sph_keccak_context *kc, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        uint64_t lane = kc->u.wide[i / 8];
        if (complemented((unsigned)(i / 8))) lane = ~lane;
        out[i] = (uint8_t)(lane >> (8 * (i % 8)));
    }
}
static void finish_state(sph_keccak_context *kc, size_t rate) {
    unsigned char padding[200] = { 1 };
    size_t remaining = rate - kc->ptr;
    padding[remaining - 1] |= 0x80;
    keccak_core(kc, padding, remaining, rate);
}
void keccakf(uint64_t state[25], int rounds) {
    sph_keccak_context context, *kc = &context;
    if (rounds < 0 || rounds > 24) abort();
    for (unsigned i = 0; i < 25; ++i)
        kc->u.wide[i] = complemented(i) ? ~state[i] : state[i];
    /* Use the licensed sphlib one-round transform, restoring its lane layout. */
    for (int j = 0; j < rounds; ++j) { DO(KF_ELT(0, 1, RC[j])); P1_TO_P0; }
    for (unsigned i = 0; i < 25; ++i)
        state[i] = complemented(i) ? ~kc->u.wide[i] : kc->u.wide[i];
}
void keccak(const uint8_t *input, size_t length, uint8_t *output, int bytes) {
    sph_keccak_context ctx;
    /* Preserve legacy accepted whole-lane digest sizes and state export. */
    if (bytes <= 0 || (bytes > 100 && bytes != 200) || bytes % 8) abort();
    size_t rate = bytes == 200 ? 136 : 200 - 2 * (size_t)bytes;
    if (rate > 144) abort();
    pc_sphlib_internal_init(&ctx, bytes == 200 ? 256 : (unsigned)bytes * 8);
    if (length) keccak_core(&ctx, input, length, rate);
    finish_state(&ctx, rate);
    export_state(&ctx, output, (size_t)bytes);
}
void keccak1600(const uint8_t *input, size_t length, uint8_t *output) {
    keccak(input, length, output, 200);
}
void keccak_init(KECCAK_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}
static void import_context(sph_keccak_context *state, const KECCAK_CTX *ctx) {
    sph_keccak256_init(state);
    for (unsigned i = 0; i < 25; ++i)
        state->u.wide[i] = complemented(i) ? ~ctx->hash[i] : ctx->hash[i];
    state->ptr = ctx->rest;
    memcpy(state->buf, ctx->message, 136);
}
static void save_context(KECCAK_CTX *ctx, const sph_keccak_context *state) {
    for (unsigned i = 0; i < 25; ++i)
        ctx->hash[i] = complemented(i) ? ~state->u.wide[i] : state->u.wide[i];
    ctx->rest = state->ptr;
    memcpy(ctx->message, state->buf, 136);
}
void keccak_update(KECCAK_CTX *ctx, const uint8_t *input, size_t length) {
    sph_keccak_context state;
    if (ctx->rest & 0x80000000U) abort();
    import_context(&state, ctx);
    if (length) sph_keccak256(&state, input, length);
    save_context(ctx, &state);
}
void keccak_finish(KECCAK_CTX *ctx, uint8_t *output) {
    if (!(ctx->rest & 0x80000000U)) {
        sph_keccak_context state;
        import_context(&state, ctx);
        finish_state(&state, 136);
        save_context(ctx, &state);
        ctx->rest = 0x80000000U;
    }
    if (output) {
        for (unsigned i = 0; i < 32; ++i)
            output[i] = (uint8_t)(ctx->hash[i / 8] >> (8 * (i % 8)));
    }
}
