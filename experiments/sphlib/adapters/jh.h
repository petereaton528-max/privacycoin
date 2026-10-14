/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 petereaton528-max
 * Independently written interface declarations; no inherited implementation. */
#ifndef PC_SPHLIB_JH_H
#define PC_SPHLIB_JH_H
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;
HashReturn jh_hash(int bits, const BitSequence *input, DataLength length_bits,
                   BitSequence *output);
#endif
