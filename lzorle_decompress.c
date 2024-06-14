/* lzorle_decompress.h
 *
 * from kernel lib/lzo/lzo1x_decompress_safe.c
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

#include "defs.h"
#include "lzorle_decompress.h"

/* This MAX_255_COUNT is the maximum number of times we can add 255 to a base
 * count without overflowing an integer. The multiply will overflow when
 * multiplying 255 by more than MAXINT/255. The sum will overflow earlier
 * depending on the base count. Since the base count is taken from a u8
 * and a few bits, it is safe to assume that it will always be lower than
 * or equal to 2*255, thus we can always prevent any overflow by accepting
 * two less 255 steps. See Documentation/lzo.txt for more information.
 */
#define MAX_255_COUNT ((((ulong)~0) / 255) - 2)

static inline uint16_t get_unaligned_le16 (const uint8_t *p) {
	return p[0] | p[1] << 8;
}

int lzorle_decompress_safe(const unsigned char *in, ulong in_len,
			  unsigned char *out, ulong *out_len, void *other/* NOT USED */) {
	unsigned char *op;
	const unsigned char *ip;
	ulong t, next;
	ulong state = 0;
	const unsigned char *m_pos;
	const unsigned char * const ip_end = in + in_len;
	unsigned char * const op_end = out + *out_len;

	unsigned char bitstream_version;

	static int efficient_unaligned_access = -1;

	if (efficient_unaligned_access == -1) {
#if defined(ARM) || defined(ARM64) || defined(X86) || defined(X86_64) || defined(PPC) || defined(PPC64) || defined(S390)|| defined(S390X)
		efficient_unaligned_access = TRUE;
#else
		efficient_unaligned_access = FALSE;
#endif

		if ((kt->ikconfig_flags & IKCONFIG_AVAIL) &&
		    (get_kernel_config("CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS", NULL) == IKCONFIG_Y))
			efficient_unaligned_access = TRUE;
	}

	op = out;
	ip = in;

	if (in_len < 3)
		goto input_overrun;

	if (in_len >= 5 && *ip == 17) {
		bitstream_version = ip[1];
		ip += 2;
	} else {
		bitstream_version = 0;
	}

	if (*ip > 17) {
		t = *ip++ - 17;
		if (t < 4) {
			next = t;
			goto match_next;
		}
		goto copy_literal_run;
	}

	for (;;) {
		t = *ip++;
		if (t < 16) {
			if (state == 0) {
				if (t == 0) {
					ulong offset;
					const unsigned char *ip_last = ip;

					while (*ip == 0) {
						ip++;
						NEED_IP(1);
					}
					offset = ip - ip_last;
					if (offset > MAX_255_COUNT)
						return LZO_E_ERROR;

					offset = (offset << 8) - offset;
					t += offset + 15 + *ip++;
				}
				t += 3;
copy_literal_run:
				if (efficient_unaligned_access &&
				    (HAVE_IP(t + 15) && HAVE_OP(t + 15))) {
					const unsigned char *ie = ip + t;
					unsigned char *oe = op + t;
					do {
						COPY8(op, ip);
						op += 8;
						ip += 8;
						COPY8(op, ip);
						op += 8;
						ip += 8;
					} while (ip < ie);
					ip = ie;
					op = oe;
				} else {
					NEED_OP(t);
					NEED_IP(t + 3);
					do {
						*op++ = *ip++;
					} while (--t > 0);
				}
				state = 4;
				continue;
			} else if (state != 4) {
				next = t & 3;
				m_pos = op - 1;
				m_pos -= t >> 2;
				m_pos -= *ip++ << 2;
				TEST_LB(m_pos);
				NEED_OP(2);
				op[0] = m_pos[0];
				op[1] = m_pos[1];
				op += 2;
				goto match_next;
			} else {
				next = t & 3;
				m_pos = op - (1 + M2_MAX_OFFSET);
				m_pos -= t >> 2;
				m_pos -= *ip++ << 2;
				t = 3;
			}
		} else if (t >= 64) {
			next = t & 3;
			m_pos = op - 1;
			m_pos -= (t >> 2) & 7;
			m_pos -= *ip++ << 3;
			t = (t >> 5) - 1 + (3 - 1);
		} else if (t >= 32) {
			t = (t & 31) + (3 - 1);
			if (t == 2) {
				ulong offset;
				const unsigned char *ip_last = ip;

				while (*ip == 0) {
					ip++;
					NEED_IP(1);
				}
				offset = ip - ip_last;
				if (offset > MAX_255_COUNT)
					return LZO_E_ERROR;

				offset = (offset << 8) - offset;
				t += offset + 31 + *ip++;
				NEED_IP(2);
			}
			m_pos = op - 1;

			next = get_unaligned_le16(ip);
			ip += 2;
			m_pos -= next >> 2;
			next &= 3;
		} else {
			NEED_IP(2);
			next = get_unaligned_le16(ip);
			if (((next & 0xfffc) == 0xfffc) &&
			    ((t & 0xf8) == 0x18) &&
			    bitstream_version) {
				NEED_IP(3);
				t &= 7;
				t |= ip[2] << 3;
				t += MIN_ZERO_RUN_LENGTH;
				NEED_OP(t);
				memset(op, 0, t);
				op += t;
				next &= 3;
				ip += 3;
				goto match_next;
			} else {
				m_pos = op;
				m_pos -= (t & 8) << 11;
				t = (t & 7) + (3 - 1);
				if (t == 2) {
					ulong offset;
					const unsigned char *ip_last = ip;

					while (*ip == 0) {
						ip++;
						NEED_IP(1);
					}
					offset = ip - ip_last;
					if (offset > MAX_255_COUNT)
						return LZO_E_ERROR;

					offset = (offset << 8) - offset;
					t += offset + 7 + *ip++;
					NEED_IP(2);
					next = get_unaligned_le16(ip);
				}
				ip += 2;
				m_pos -= next >> 2;
				next &= 3;
				if (m_pos == op)
					goto eof_found;
				m_pos -= 0x4000;
			}
		}
		TEST_LB(m_pos);

		if (efficient_unaligned_access &&
		    (op - m_pos >= 8)) {
			unsigned char *oe = op + t;
			if (HAVE_OP(t + 15)) {
				do {
					COPY8(op, m_pos);
					op += 8;
					m_pos += 8;
					COPY8(op, m_pos);
					op += 8;
					m_pos += 8;
				} while (op < oe);
				op = oe;
				if (HAVE_IP(6)) {
					state = next;
					COPY4(op, ip);
					op += next;
					ip += next;
					continue;
				}
			} else {
				NEED_OP(t);
				do {
					*op++ = *m_pos++;
				} while (op < oe);
			}
		} else {
			unsigned char *oe = op + t;
			NEED_OP(t);
			op[0] = m_pos[0];
			op[1] = m_pos[1];
			op += 2;
			m_pos += 2;
			do {
				*op++ = *m_pos++;
			} while (op < oe);
		}
match_next:
		state = next;
		t = next;
		if (efficient_unaligned_access &&
		    (HAVE_IP(6) && HAVE_OP(4))) {
			COPY4(op, ip);
			op += t;
			ip += t;
		} else {
			NEED_IP(t + 3);
			NEED_OP(t);
			while (t > 0) {
				*op++ = *ip++;
				t--;
			}
		}
	}

eof_found:
	*out_len = op - out;
	return (t != 3       ? LZO_E_ERROR :
		ip == ip_end ? LZO_E_OK :
		ip <  ip_end ? LZO_E_INPUT_NOT_CONSUMED : LZO_E_INPUT_OVERRUN);

input_overrun:
	*out_len = op - out;
	return LZO_E_INPUT_OVERRUN;

output_overrun:
	*out_len = op - out;
	return LZO_E_OUTPUT_OVERRUN;

lookbehind_overrun:
	*out_len = op - out;
	return LZO_E_LOOKBEHIND_OVERRUN;
}
