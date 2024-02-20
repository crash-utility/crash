/* lzorle_decompress.h
 *
 * from kernel lib/lzo/lzodefs.h
 *
 * Copyright (C) 1996-2012 Markus F.X.J. Oberhumer <mar...@oberhumer.com>
 * Copyright (C) 2024 NIO
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef LZODEFS_H
#define LZODEFS_H

#define COPY4(dst, src) memcpy((dst), (src), sizeof(uint32_t))
#define COPY8(dst, src) memcpy((dst), (src), sizeof(uint64_t))

#define M1_MAX_OFFSET 0x0400
#define M2_MAX_OFFSET 0x0800
#define M3_MAX_OFFSET 0x4000
#define M4_MAX_OFFSET_V0 0xbfff
#define M4_MAX_OFFSET_V1 0xbffe

#define M1_MIN_LEN 2
#define M1_MAX_LEN 2
#define M2_MIN_LEN 3
#define M2_MAX_LEN 8
#define M3_MIN_LEN 3
#define M3_MAX_LEN 33
#define M4_MIN_LEN 3
#define M4_MAX_LEN 9

#define M1_MARKER 0
#define M2_MARKER 64
#define M3_MARKER 32
#define M4_MARKER 16

#define MIN_ZERO_RUN_LENGTH 4
#define MAX_ZERO_RUN_LENGTH (2047 + MIN_ZERO_RUN_LENGTH)

#define lzo_dict_t unsigned short
#define D_BITS 13
#define D_SIZE (1u << D_BITS)
#define D_MASK (D_SIZE - 1)
#define D_HIGH ((D_MASK >> 1) + 1)

#define LZO_E_OK 0
#define LZO_E_ERROR (-1)
#define LZO_E_OUT_OF_MEMORY (-2)
#define LZO_E_NOT_COMPRESSIBLE (-3)
#define LZO_E_INPUT_OVERRUN (-4)
#define LZO_E_OUTPUT_OVERRUN (-5)
#define LZO_E_LOOKBEHIND_OVERRUN (-6)
#define LZO_E_EOF_NOT_FOUND (-7)
#define LZO_E_INPUT_NOT_CONSUMED (-8)
#define LZO_E_NOT_YET_IMPLEMELZO_HFILESNTED (-9)
#define LZO_E_INVALID_ARGUMENT (-10)

#define HAVE_IP(x)	((unsigned long)(ip_end - ip) >= (unsigned long)(x))
#define HAVE_OP(x)	((unsigned long)(op_end - op) >= (unsigned long)(x))
#define NEED_IP(x)	if (!HAVE_IP(x)) goto input_overrun
#define NEED_OP(x)	if (!HAVE_OP(x)) goto output_overrun
#define TEST_LB(m_pos)	if ((m_pos) < out) goto lookbehind_overrun

int lzorle_decompress_safe(const unsigned char *in, unsigned long in_len,
			  unsigned char *out, unsigned long *out_len, void *other/* NOT USED */);

#endif
