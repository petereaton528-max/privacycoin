/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 petereaton528-max
 * Source-compatible API. Context is internal, not a persisted or wire format. */
#ifndef PC_SPHLIB_KECCAK_H
#define PC_SPHLIB_KECCAK_H
#include <stdint.h>
#include <stddef.h>
typedef struct { uint64_t hash[25]; uint64_t message[17]; size_t rest; } KECCAK_CTX;
void keccak(const uint8_t *, size_t, uint8_t *, int);
void keccak1600(const uint8_t *, size_t, uint8_t *);
void keccakf(uint64_t [25], int);
void keccak_init(KECCAK_CTX *);
void keccak_update(KECCAK_CTX *, const uint8_t *, size_t);
void keccak_finish(KECCAK_CTX *, uint8_t *);
#endif
