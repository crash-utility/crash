/*
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

#if defined(X86_64)
/*
 * Support for genarating DWARF CFI based backtraces.
 * Borrowed heavily from the kernel's implementation of unwinding using the
 * DWARF CFI written by Jan Beulich
 */

#ifdef X86_64
#include "unwind_x86_64.h"
#endif
#ifdef X86
#include "unwind_x86.h"
#endif

#include "defs.h"

#define MAX_STACK_DEPTH 8

static struct local_unwind_table {
        struct {
                unsigned long pc;
                unsigned long range;
        } core, init;
        void *address;
        unsigned long size;
} *local_unwind_tables, default_unwind_table;

static int gather_in_memory_unwind_tables(void);
static int populate_local_tables(ulong, char *);
static int unwind_tables_cnt = 0;
static struct local_unwind_table *find_table(unsigned long);
static void dump_local_unwind_tables(void);

static const struct {
	unsigned offs:BITS_PER_LONG / 2;
	unsigned width:BITS_PER_LONG / 2;
} reg_info[] = {
	UNW_REGISTER_INFO
};

#undef PTREGS_INFO
#undef EXTRA_INFO

#ifndef REG_INVALID
#define REG_INVALID(r) (reg_info[r].width == 0)
#endif

#define DW_CFA_nop                          0x00
#define DW_CFA_set_loc                      0x01
#define DW_CFA_advance_loc1                 0x02
#define DW_CFA_advance_loc2                 0x03
#define DW_CFA_advance_loc4                 0x04
#define DW_CFA_offset_extended              0x05
#define DW_CFA_restore_extended             0x06
#define DW_CFA_undefined                    0x07
#define DW_CFA_same_value                   0x08
#define DW_CFA_register                     0x09
#define DW_CFA_remember_state               0x0a
#define DW_CFA_restore_state                0x0b
#define DW_CFA_def_cfa                      0x0c
#define DW_CFA_def_cfa_register             0x0d
#define DW_CFA_def_cfa_offset               0x0e
#define DW_CFA_def_cfa_expression           0x0f
#define DW_CFA_expression                   0x10
#define DW_CFA_offset_extended_sf           0x11
#define DW_CFA_def_cfa_sf                   0x12
#define DW_CFA_def_cfa_offset_sf            0x13
#define DW_CFA_val_offset                   0x14
#define DW_CFA_val_offset_sf                0x15
#define DW_CFA_val_expression               0x16
#define DW_CFA_lo_user                      0x1c
#define DW_CFA_GNU_window_save              0x2d
#define DW_CFA_GNU_args_size                0x2e
#define DW_CFA_GNU_negative_offset_extended 0x2f
#define DW_CFA_hi_user                      0x3f

#define DW_EH_PE_FORM     0x07
#define DW_EH_PE_native   0x00
#define DW_EH_PE_leb128   0x01
#define DW_EH_PE_data2    0x02
#define DW_EH_PE_data4    0x03
#define DW_EH_PE_data8    0x04
#define DW_EH_PE_signed   0x08
#define DW_EH_PE_ADJUST   0x70
#define DW_EH_PE_abs      0x00
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_textrel  0x20
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_funcrel  0x40
#define DW_EH_PE_aligned  0x50
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit     0xff

#define min(x,y) ({ \
        typeof(x) _x = (x);     \
        typeof(y) _y = (y);     \
        (void) (&_x == &_y);            \
        _x < _y ? _x : _y; })

#define max(x,y) ({ \
        typeof(x) _x = (x);     \
        typeof(y) _y = (y);     \
        (void) (&_x == &_y);            \
        _x > _y ? _x : _y; })
#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

typedef unsigned long uleb128_t;
typedef   signed long sleb128_t;

struct unwind_item {
	enum item_location {
		Nowhere,
		Memory,
		Register,
		Value
	} where;
	uleb128_t value;
};

struct unwind_state {
	uleb128_t loc, org;
	const u8 *cieStart, *cieEnd;
	uleb128_t codeAlign;
	sleb128_t dataAlign;
	struct cfa {
		uleb128_t reg, offs;
	} cfa;
	struct unwind_item regs[ARRAY_SIZE(reg_info)];
	unsigned stackDepth:8;
	unsigned version:8;
	const u8 *label;
	const u8 *stack[MAX_STACK_DEPTH];
};

static const struct cfa badCFA = { ARRAY_SIZE(reg_info), 1 };

static uleb128_t get_uleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	uleb128_t value;
	unsigned shift;

	for (shift = 0, value = 0; cur < end; shift += 7) {
		if (shift + 7 > 8 * sizeof(value)
		    && (*cur & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (uleb128_t)(*cur & 0x7f) << shift;
		if (!(*cur++ & 0x80))
			break;
	}
	*pcur = cur;

	return value;
}

static sleb128_t get_sleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	sleb128_t value;
	unsigned shift;

	for (shift = 0, value = 0; cur < end; shift += 7) {
		if (shift + 7 > 8 * sizeof(value)
		    && (*cur & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (sleb128_t)(*cur & 0x7f) << shift;
		if (!(*cur & 0x80)) {
			value |= -(*cur++ & 0x40) << shift;
			break;
		}
	}
	*pcur = cur;

	return value;
}

static unsigned long read_pointer(const u8 **pLoc,
                                  const void *end,
                                  signed ptrType)
{
	unsigned long value = 0;
	union {
		const u8 *p8;
		const u16 *p16u;
		const s16 *p16s;
		const u32 *p32u;
		const s32 *p32s;
		const unsigned long *pul;
	} ptr;

	if (ptrType < 0 || ptrType == DW_EH_PE_omit)
		return 0;
	ptr.p8 = *pLoc;
	switch(ptrType & DW_EH_PE_FORM) {
	case DW_EH_PE_data2:
		if (end < (const void *)(ptr.p16u + 1))
			return 0;
		if(ptrType & DW_EH_PE_signed)
			value = get_unaligned(ptr.p16s++);
		else
			value = get_unaligned(ptr.p16u++);
		break;
	case DW_EH_PE_data4:
#ifdef CONFIG_64BIT
		if (end < (const void *)(ptr.p32u + 1))
			return 0;
		if(ptrType & DW_EH_PE_signed)
			value = get_unaligned(ptr.p32s++);
		else
			value = get_unaligned(ptr.p32u++);
		break;
	case DW_EH_PE_data8:
		BUILD_BUG_ON(sizeof(u64) != sizeof(value));
#else
		BUILD_BUG_ON(sizeof(u32) != sizeof(value));
#endif
	case DW_EH_PE_native:
		if (end < (const void *)(ptr.pul + 1))
			return 0;
		value = get_unaligned(ptr.pul++);
		break;
	case DW_EH_PE_leb128:
		BUILD_BUG_ON(sizeof(uleb128_t) > sizeof(value));
		value = ptrType & DW_EH_PE_signed
		        ? get_sleb128(&ptr.p8, end)
		        : get_uleb128(&ptr.p8, end);
		if ((const void *)ptr.p8 > end)
			return 0;
		break;
	default:
		return 0;
	}
	switch(ptrType & DW_EH_PE_ADJUST) {
	case DW_EH_PE_abs:
		break;
	case DW_EH_PE_pcrel:
		value += (unsigned long)*pLoc;
		break;
	default:
		return 0;
	}

/*	TBD
	if ((ptrType & DW_EH_PE_indirect)
	    && __get_user(value, (unsigned long *)value))
		return 0;
*/
	*pLoc = ptr.p8;

	return value;
}

static signed fde_pointer_type(const u32 *cie)
{
	const u8 *ptr = (const u8 *)(cie + 2);
	unsigned version = *ptr;

	if (version != 1)
		return -1; /* unsupported */
	if (*++ptr) {
		const char *aug;
		const u8 *end = (const u8 *)(cie + 1) + *cie;
		uleb128_t len;

		/* check if augmentation size is first (and thus present) */
		if (*ptr != 'z')
			return -1;
		/* check if augmentation string is nul-terminated */
		if ((ptr = memchr(aug = (const void *)ptr, 0, end - ptr)) == NULL)
			return -1;
		++ptr; /* skip terminator */
		get_uleb128(&ptr, end); /* skip code alignment */
		get_sleb128(&ptr, end); /* skip data alignment */
		/* skip return address column */
		version <= 1 ? (void)++ptr : (void)get_uleb128(&ptr, end);
		len = get_uleb128(&ptr, end); /* augmentation length */
		if (ptr + len < ptr || ptr + len > end)
			return -1;
		end = ptr + len;
		while (*++aug) {
			if (ptr >= end)
				return -1;
			switch(*aug) {
			case 'L':
				++ptr;
				break;
			case 'P': {
					signed ptrType = *ptr++;

					if (!read_pointer(&ptr, end, ptrType) || 					     ptr > end)
						return -1;
				}
				break;
			case 'R':
				return *ptr;
			default:
				return -1;
			}
		}
	}
	return DW_EH_PE_native|DW_EH_PE_abs;
}

static int advance_loc(unsigned long delta, struct unwind_state *state)
{
	state->loc += delta * state->codeAlign;

	return delta > 0;
}

static void set_rule(uleb128_t reg,
                     enum item_location where,
                     uleb128_t value,
                     struct unwind_state *state)
{
	if (reg < ARRAY_SIZE(state->regs)) {
		state->regs[reg].where = where;
		state->regs[reg].value = value;
	}
}

static int processCFI(const u8 *start,
                      const u8 *end,
                      unsigned long targetLoc,
                      signed ptrType,
                      struct unwind_state *state)
{
	union {
		const u8 *p8;
		const u16 *p16;
		const u32 *p32;
	} ptr;
	int result = 1;

	if (start != state->cieStart) {
		state->loc = state->org;
		result = processCFI(state->cieStart, state->cieEnd, 0, ptrType, state);
		if (targetLoc == 0 && state->label == NULL)
			return result;
	}
	for (ptr.p8 = start; result && ptr.p8 < end; ) {
		switch(*ptr.p8 >> 6) {
			uleb128_t value;

		case 0:
			switch(*ptr.p8++) {
			case DW_CFA_nop:
				break;
			case DW_CFA_set_loc:
				if ((state->loc = read_pointer(&ptr.p8, end,
								ptrType)) == 0)
					result = 0;
				break;
			case DW_CFA_advance_loc1:
				result = ptr.p8 < end && advance_loc(*ptr.p8++, state);
				break;
			case DW_CFA_advance_loc2:
				result = ptr.p8 <= end + 2
				         && advance_loc(*ptr.p16++, state);
				break;
			case DW_CFA_advance_loc4:
				result = ptr.p8 <= end + 4
				         && advance_loc(*ptr.p32++, state);
				break;
			case DW_CFA_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Memory,
					get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_val_offset:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Value,
					get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_offset_extended_sf:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Memory,
					get_sleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_val_offset_sf:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Value,
					get_sleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_restore_extended:
			case DW_CFA_undefined:
			case DW_CFA_same_value:
				set_rule(get_uleb128(&ptr.p8, end), Nowhere, 0,	state);
				break;
			case DW_CFA_register:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Register,
				         get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_remember_state:
				if (ptr.p8 == state->label) {
					state->label = NULL;
					return 1;
				}
				if (state->stackDepth >= MAX_STACK_DEPTH)
					return 0;
				state->stack[state->stackDepth++] = ptr.p8;
				break;
			case DW_CFA_restore_state:
				if (state->stackDepth) {
					const uleb128_t loc = state->loc;
					const u8 *label = state->label;

					state->label = state->stack[state->stackDepth - 1];
					memcpy(&state->cfa, &badCFA, sizeof(state->cfa));
					memset(state->regs, 0, sizeof(state->regs));
					state->stackDepth = 0;
					result = processCFI(start, end, 0, ptrType, state);
					state->loc = loc;
					state->label = label;
				} else
					return 0;
				break;
			case DW_CFA_def_cfa:
				state->cfa.reg = get_uleb128(&ptr.p8, end);
				/*nobreak*/
			case DW_CFA_def_cfa_offset:
				state->cfa.offs = get_uleb128(&ptr.p8, end);
				break;
			case DW_CFA_def_cfa_sf:
				state->cfa.reg = get_uleb128(&ptr.p8, end);
				/*nobreak*/
			case DW_CFA_def_cfa_offset_sf:
				state->cfa.offs = get_sleb128(&ptr.p8, end)
				                  * state->dataAlign;
				break;
			case DW_CFA_def_cfa_register:
				state->cfa.reg = get_uleb128(&ptr.p8, end);
				break;
			/*todo case DW_CFA_def_cfa_expression: */
			/*todo case DW_CFA_expression: */
			/*todo case DW_CFA_val_expression: */
			case DW_CFA_GNU_args_size:
				get_uleb128(&ptr.p8, end);
				break;
			case DW_CFA_GNU_negative_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Memory, (uleb128_t)0 -
				         get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_GNU_window_save:
			default:
				result = 0;
				break;
			}
			break;
		case 1:
			result = advance_loc(*ptr.p8++ & 0x3f, state);
			break;
		case 2:
			value = *ptr.p8++ & 0x3f;
			set_rule(value, Memory, get_uleb128(&ptr.p8, end),
				 state);
			break;
		case 3:
			set_rule(*ptr.p8++ & 0x3f, Nowhere, 0, state);
			break;
		}
		if (ptr.p8 > end)
			result = 0;
		if (result && targetLoc != 0 && targetLoc < state->loc)
			return 1;
	}

	return result
	   && ptr.p8 == end
	   && (targetLoc == 0
	    || (/*todo While in theory this should apply, gcc in practice omits
	          everything past the function prolog, and hence the location
	          never reaches the end of the function.
	        targetLoc < state->loc &&*/ state->label == NULL));
}


/* Unwind to previous to frame.  Returns 0 if successful, negative
 * number in case of an error. */
int 
unwind(struct unwind_frame_info *frame, int is_ehframe)
{
#define FRAME_REG(r, t) (((t *)frame)[reg_info[r].offs])
	const u32 *fde = NULL, *cie = NULL;
	const u8 *ptr = NULL, *end = NULL;
	unsigned long startLoc = 0, endLoc = 0, cfa;
	unsigned i;
	signed ptrType = -1;
	uleb128_t retAddrReg = 0;
//	struct unwind_table *table;
	void *unwind_table;
	struct local_unwind_table *table;
	struct unwind_state state;
	u64 reg_ptr = 0;


	if (UNW_PC(frame) == 0)
		return -EINVAL;

	if ((table = find_table(UNW_PC(frame)))) {
//		unsigned long tableSize = unwind_table_size;
		unsigned long tableSize = table->size;

		unwind_table = table->address;

		for (fde = unwind_table;
		     tableSize > sizeof(*fde) && tableSize - sizeof(*fde) >= *fde;
		     tableSize -= sizeof(*fde) + *fde,
		     fde += 1 + *fde / sizeof(*fde)) {
			if (!*fde || (*fde & (sizeof(*fde) - 1)))
				break;
			if (is_ehframe && !fde[1])
				continue; /* this is a CIE */
			else if (fde[1] == 0xffffffff)
				continue; /* this is a CIE */
			if ((fde[1] & (sizeof(*fde) - 1))
			    || fde[1] > (unsigned long)(fde + 1)
			                - (unsigned long)unwind_table)
				continue; /* this is not a valid FDE */
			if (is_ehframe)
				cie = fde + 1 - fde[1] / sizeof(*fde);
			else
				cie = unwind_table + fde[1];
			if (*cie <= sizeof(*cie) + 4
			    || *cie >= fde[1] - sizeof(*fde)
			    || (*cie & (sizeof(*cie) - 1))
			    || (cie[1] != 0xffffffff && cie[1])
			    || (ptrType = fde_pointer_type(cie)) < 0) {
				cie = NULL; /* this is not a (valid) CIE */
				continue;
			}
			ptr = (const u8 *)(fde + 2);
			startLoc = read_pointer(&ptr,
			                        (const u8 *)(fde + 1) + *fde,
			                        ptrType);
			endLoc = startLoc
			         + read_pointer(&ptr,
			                        (const u8 *)(fde + 1) + *fde,
			                        ptrType & DW_EH_PE_indirect
			                        ? ptrType
			                        : ptrType & (DW_EH_PE_FORM|DW_EH_PE_signed));
			if (UNW_PC(frame) >= startLoc && UNW_PC(frame) < endLoc)
				break;
			cie = NULL;
		}
	}
	if (cie != NULL) {
		memset(&state, 0, sizeof(state));
		state.cieEnd = ptr; /* keep here temporarily */
		ptr = (const u8 *)(cie + 2);
		end = (const u8 *)(cie + 1) + *cie;
		if ((state.version = *ptr) != 1)
			cie = NULL; /* unsupported version */
		else if (*++ptr) {
			/* check if augmentation size is first (and thus present) */
			if (*ptr == 'z') {
				/* check for ignorable (or already handled)
				 * nul-terminated augmentation string */
				while (++ptr < end && *ptr)
					if (strchr("LPR", *ptr) == NULL)
						break;
			}
			if (ptr >= end || *ptr)
				cie = NULL;
		}
		++ptr;
	}
	if (cie != NULL) {
		/* get code aligment factor */
		state.codeAlign = get_uleb128(&ptr, end);
		/* get data aligment factor */
		state.dataAlign = get_sleb128(&ptr, end);
		if (state.codeAlign == 0 || state.dataAlign == 0 || ptr >= end)
			cie = NULL;
		else {
			retAddrReg = state.version <= 1 ? *ptr++ : get_uleb128(&ptr, end);
			/* skip augmentation */
			if (((const char *)(cie + 2))[1] == 'z')
				ptr += get_uleb128(&ptr, end);
			if (ptr > end
			   || retAddrReg >= ARRAY_SIZE(reg_info)
			   || REG_INVALID(retAddrReg)
			   || reg_info[retAddrReg].width != sizeof(unsigned long))
				cie = NULL;
		}
	}
	if (cie != NULL) {
		state.cieStart = ptr;
		ptr = state.cieEnd;
		state.cieEnd = end;
		end = (const u8 *)(fde + 1) + *fde;
		/* skip augmentation */
		if (((const char *)(cie + 2))[1] == 'z') {
			uleb128_t augSize = get_uleb128(&ptr, end);

			if ((ptr += augSize) > end)
				fde = NULL;
		}
	}
	if (cie == NULL || fde == NULL)
		return -ENXIO;

	state.org = startLoc;
	memcpy(&state.cfa, &badCFA, sizeof(state.cfa));
	/* process instructions */
	if (!processCFI(ptr, end, UNW_PC(frame), ptrType, &state)
	   || state.loc > endLoc
	   || state.regs[retAddrReg].where == Nowhere
	   || state.cfa.reg >= ARRAY_SIZE(reg_info)
	   || reg_info[state.cfa.reg].width != sizeof(unsigned long)
	   || state.cfa.offs % sizeof(unsigned long)) {
		return -EIO;
		}
	/* update frame */
	cfa = FRAME_REG(state.cfa.reg, unsigned long) + state.cfa.offs;
	startLoc = min((unsigned long)UNW_SP(frame), cfa);
	endLoc = max((unsigned long)UNW_SP(frame), cfa);
	if (STACK_LIMIT(startLoc) != STACK_LIMIT(endLoc)) {
		startLoc = min(STACK_LIMIT(cfa), cfa);
		endLoc = max(STACK_LIMIT(cfa), cfa);
	}
#ifndef CONFIG_64BIT
# define CASES CASE(8); CASE(16); CASE(32)
#else
# define CASES CASE(8); CASE(16); CASE(32); CASE(64)
#endif
	for (i = 0; i < ARRAY_SIZE(state.regs); ++i) {
		if (REG_INVALID(i)) {
			if (state.regs[i].where == Nowhere)
				continue;
			return -EIO;
		}
		switch(state.regs[i].where) {
		default:
			break;
		case Register:
			if (state.regs[i].value >= ARRAY_SIZE(reg_info)
			   || REG_INVALID(state.regs[i].value)
			   || reg_info[i].width > reg_info[state.regs[i].value].width){
				return -EIO;
	}
			switch(reg_info[state.regs[i].value].width) {
#define CASE(n) \
			case sizeof(u##n): \
				state.regs[i].value = FRAME_REG(state.regs[i].value, \
				                                const u##n); \
				break
			CASES;
#undef CASE
			default:
				return -EIO;
			}
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(state.regs); ++i) {
		if (REG_INVALID(i))
			continue;
		switch(state.regs[i].where) {
		case Nowhere:
			if (reg_info[i].width != sizeof(UNW_SP(frame))
			   || &FRAME_REG(i, __typeof__(UNW_SP(frame)))
			      != &UNW_SP(frame))
				continue;
			UNW_SP(frame) = cfa;
			break;
		case Register:
			switch(reg_info[i].width) {
#define CASE(n) case sizeof(u##n): \
				FRAME_REG(i, u##n) = state.regs[i].value; \
				break
			CASES;
#undef CASE
			default:
				return -EIO;
			}
			break;
		case Value:
			if (reg_info[i].width != sizeof(unsigned long)){
				return -EIO;}
			FRAME_REG(i, unsigned long) = cfa + state.regs[i].value
			                                    * state.dataAlign;
			break;
		case Memory: {
				unsigned long addr = cfa + state.regs[i].value
				                           * state.dataAlign;
				if ((state.regs[i].value * state.dataAlign)
				    % sizeof(unsigned long)
				    || addr < startLoc
				    || addr + sizeof(unsigned long) < addr
				    || addr + sizeof(unsigned long) > endLoc){
					return -EIO;}
				switch(reg_info[i].width) {
#define CASE(n)     case sizeof(u##n): \
					readmem(addr, KVADDR, &reg_ptr,sizeof(u##n), "register", RETURN_ON_ERROR|QUIET); \
					FRAME_REG(i, u##n) = (u##n)reg_ptr;\
					break
				CASES;
#undef CASE
				default:
					return -EIO;
				}
			}
			break;
		}
	}
	return 0;
#undef CASES
#undef FRAME_REG
}

/*
 *  Initialize the unwind table(s) in the best-case order:
 *
 *   1. Use the in-memory kernel and module unwind tables.
 *   2. Use the in-memory kernel-only .eh_frame data. (possible?)
 *   3. Use the kernel-only .eh_frame data from the vmlinux file.
 */ 
void 
init_unwind_table(void)
{
	ulong unwind_table_size;
	void *unwind_table;

	kt->flags &= ~DWARF_UNWIND;

	if (gather_in_memory_unwind_tables()) {
                if (CRASHDEBUG(1))
                        fprintf(fp, "init_unwind_table: DWARF_UNWIND_MEMORY (%d tables)\n",
				unwind_tables_cnt);

                kt->flags |= DWARF_UNWIND_MEMORY;
		if (unwind_tables_cnt > 1)
                	kt->flags |= DWARF_UNWIND_MODULES;
                if (!(kt->flags & NO_DWARF_UNWIND))
                        kt->flags |= DWARF_UNWIND;

		return;
	}

	if (symbol_exists("__start_unwind") &&
	    symbol_exists("__end_unwind")) {
		unwind_table_size = symbol_value("__end_unwind") - 
			symbol_value("__start_unwind");

		if (!(unwind_table = malloc(unwind_table_size))) {
			error(WARNING, "cannot malloc unwind table space\n");
			goto try_eh_frame;
		}

		if (!readmem(symbol_value("__start_unwind"), KVADDR, unwind_table,
            	    unwind_table_size, "unwind table", RETURN_ON_ERROR)) {
			error(WARNING, "cannot read unwind table data\n");
			free(unwind_table);
			goto try_eh_frame;
		}

		kt->flags |= DWARF_UNWIND_MEMORY;
		if (!(kt->flags & NO_DWARF_UNWIND))
			kt->flags |= DWARF_UNWIND;

		default_unwind_table.size = unwind_table_size;
		default_unwind_table.address = unwind_table;

		if (CRASHDEBUG(1)) 
			fprintf(fp, "init_unwind_table: DWARF_UNWIND_MEMORY\n");

		return;
	}

try_eh_frame:

	if (st->dwarf_eh_frame_size || st->dwarf_debug_frame_size) {
		int fd;
		int is_ehframe = (!st->dwarf_debug_frame_size &&
				   st->dwarf_eh_frame_size);

		unwind_table_size = is_ehframe ? st->dwarf_eh_frame_size :
						 st->dwarf_debug_frame_size;

		if (!(unwind_table = malloc(unwind_table_size))) {
			error(WARNING, "cannot malloc unwind table space\n");
			return;
		}

		if ((fd = open(pc->namelist, O_RDONLY)) < 0) {
			error(WARNING, "cannot open %s for %s data\n",
				pc->namelist, is_ehframe ? ".eh_frame" : ".debug_frame");
			free(unwind_table);
			return;
		}

		if (is_ehframe)
			lseek(fd, st->dwarf_eh_frame_file_offset, SEEK_SET);
		else
			lseek(fd, st->dwarf_debug_frame_file_offset, SEEK_SET);

		if (read(fd, unwind_table, unwind_table_size) !=
		    unwind_table_size) {
			if (CRASHDEBUG(1))
				error(WARNING, "cannot read %s data from %s\n",
			        	is_ehframe ? ".eh_frame" : ".debug_frame", pc->namelist);
			free(unwind_table);
			close(fd);
			return;
		}

		close(fd);

		default_unwind_table.size = unwind_table_size;
		default_unwind_table.address = unwind_table;

		kt->flags |= DWARF_UNWIND_EH_FRAME;
		if (!(kt->flags & NO_DWARF_UNWIND))
			kt->flags |= DWARF_UNWIND;

		if (CRASHDEBUG(1)) 
			fprintf(fp, "init_unwind_table: DWARF_UNWIND_EH_FRAME\n");

		return;
	}
}

/*
 *  Find the appropriate kernel-only "root_table" unwind_table,
 *  and pass it to populate_local_tables() to do the heavy lifting.
 */
static int 
gather_in_memory_unwind_tables(void)
{
	int i, cnt, found;
	struct syment *sp, *root_tables[10];
	char *root_table_buf;
	char buf[BUFSIZE];
	ulong name;

	STRUCT_SIZE_INIT(unwind_table, "unwind_table");
	MEMBER_OFFSET_INIT(unwind_table_core, "unwind_table", "core");
	MEMBER_OFFSET_INIT(unwind_table_init, "unwind_table", "init");
	MEMBER_OFFSET_INIT(unwind_table_address, "unwind_table", "address");
	MEMBER_OFFSET_INIT(unwind_table_size, "unwind_table", "size");
	MEMBER_OFFSET_INIT(unwind_table_link, "unwind_table", "link");
	MEMBER_OFFSET_INIT(unwind_table_name, "unwind_table", "name");

	if (INVALID_SIZE(unwind_table) ||
	    INVALID_MEMBER(unwind_table_core) ||
	    INVALID_MEMBER(unwind_table_init) ||
	    INVALID_MEMBER(unwind_table_address) ||
	    INVALID_MEMBER(unwind_table_size) ||
	    INVALID_MEMBER(unwind_table_link) ||
	    INVALID_MEMBER(unwind_table_name)) {
		if (CRASHDEBUG(1)) 
			error(NOTE, 
	    "unwind_table structure has changed, or does not exist in this kernel\n");
		return 0;
	}

	/*
	 *  Unfortunately there are two kernel root_table symbols.
	 */
	if (!(cnt = get_syment_array("root_table", root_tables, 10)))
		return 0;

	root_table_buf = GETBUF(SIZE(unwind_table));
	for (i = found = 0; i < cnt; i++) {
		sp = root_tables[i];
		if (!readmem(sp->value, KVADDR, root_table_buf,
                    SIZE(unwind_table), "root unwind_table", 
		    RETURN_ON_ERROR|QUIET))
			goto gather_failed;

		name = ULONG(root_table_buf + OFFSET(unwind_table_name));
		if (read_string(name, buf, strlen("kernel")+1) && 
		    STREQ("kernel", buf)) {
			found++;
			if (CRASHDEBUG(1))
				fprintf(fp, "root_table name: %lx [%s]\n", 
					name, buf);
			break;
		}
	}

	if (!found)
		goto gather_failed;

	cnt = populate_local_tables(sp->value, root_table_buf);

	FREEBUF(root_table_buf);
	return cnt;

gather_failed:

	FREEBUF(root_table_buf);
	return 0;
}

/*
 *  Transfer the relevant data from the kernel and module unwind_table
 *  structures to the local_unwind_table structures.
 */
static int
populate_local_tables(ulong root, char *buf)
{
	struct list_data list_data, *ld;
	int i, cnt;
	ulong *table_list;
	ulong vaddr;
	struct local_unwind_table *tp;

        ld = &list_data;
        BZERO(ld, sizeof(struct list_data));
        ld->start = root;
        ld->member_offset = OFFSET(unwind_table_link);
	ld->flags = RETURN_ON_LIST_ERROR;
	if (CRASHDEBUG(1))
        	ld->flags |= VERBOSE;

	hq_open();
        cnt = do_list(ld);
	if (cnt == -1) {
		error(WARNING, "UNWIND: failed to gather unwind_table list");
		return 0;
	}
        table_list = (ulong *)GETBUF(cnt * sizeof(ulong));
	cnt = retrieve_list(table_list, cnt);
	hq_close();

	if (!(local_unwind_tables = 
	    malloc(sizeof(struct local_unwind_table) * cnt))) {
		error(WARNING, "cannot malloc unwind_table space (%d tables)\n",
			cnt);
		FREEBUF(table_list);
		return 0;
	}

	for (i = 0; i < cnt; i++, tp++) {

                if (!readmem(table_list[i], KVADDR, buf,
                    SIZE(unwind_table), "unwind_table",
                    RETURN_ON_ERROR|QUIET)) {
			error(WARNING, "cannot read unwind_table\n");
			goto failed;
		}

		tp = &local_unwind_tables[i];

		/*
		 *  Copy the required table info for find_table().
		 */
        	BCOPY(buf + OFFSET(unwind_table_core),
                	(char *)&tp->core.pc, sizeof(ulong)*2);
        	BCOPY(buf + OFFSET(unwind_table_init),
                	(char *)&tp->init.pc, sizeof(ulong)*2);
        	BCOPY(buf + OFFSET(unwind_table_size),
                	(char *)&tp->size, sizeof(ulong));

		/*
		 *  Then read the DWARF CFI data.
		 */
		vaddr = ULONG(buf + OFFSET(unwind_table_address));

		if (!(tp->address = malloc(tp->size))) {
			error(WARNING, "cannot malloc unwind_table space\n");
			goto failed;
			break;
		}
                if (!readmem(vaddr, KVADDR, tp->address,
                    tp->size, "DWARF CFI data", RETURN_ON_ERROR|QUIET)) {
			error(WARNING, "cannot read unwind_table data\n");
			goto failed;
		}
	}

	unwind_tables_cnt = cnt;

	if (CRASHDEBUG(7))
		dump_local_unwind_tables();

failed:

	FREEBUF(table_list);
	return unwind_tables_cnt;
}

/*
 *  Find the unwind_table containing a pc.
 */
static struct local_unwind_table *
find_table(unsigned long pc)
{
	int i;
	struct local_unwind_table *tp, *table;

	table = &default_unwind_table;

        for (i = 0; i < unwind_tables_cnt; i++, tp++) {
		tp = &local_unwind_tables[i];
                if ((pc >= tp->core.pc
                    && pc < tp->core.pc + tp->core.range)
                    || (pc >= tp->init.pc
                    && pc < tp->init.pc + tp->init.range)) {
			table = tp;
                        break;
		}
	}

        return table;
}

static void 
dump_local_unwind_tables(void)
{
	int i, others; 
	struct local_unwind_table *tp;

	others = 0;
	fprintf(fp, "DWARF flags: (");
        if (kt->flags & DWARF_UNWIND)
                fprintf(fp, "%sDWARF_UNWIND", others++ ? "|" : "");
        if (kt->flags & NO_DWARF_UNWIND)
                fprintf(fp, "%sNO_DWARF_UNWIND", others++ ? "|" : "");
        if (kt->flags & DWARF_UNWIND_MEMORY)
                fprintf(fp, "%sDWARF_UNWIND_MEMORY", others++ ? "|" : "");
        if (kt->flags & DWARF_UNWIND_EH_FRAME)
                fprintf(fp, "%sDWARF_UNWIND_EH_FRAME", others++ ? "|" : "");
        if (kt->flags & DWARF_UNWIND_MODULES)
                fprintf(fp, "%sDWARF_UNWIND_MODULES", others++ ? "|" : "");
	fprintf(fp, ")\n\n");

	fprintf(fp, "default_unwind_table:\n");
	fprintf(fp, "      address: %lx\n",
		(ulong)default_unwind_table.address);
	fprintf(fp, "         size: %ld\n\n",
		(ulong)default_unwind_table.size);

	fprintf(fp, "local_unwind_tables[%d]:\n", unwind_tables_cnt);
        for (i = 0; i < unwind_tables_cnt; i++, tp++) {
		tp = &local_unwind_tables[i];
		fprintf(fp, "[%d]\n", i);
		fprintf(fp, "         core: pc: %lx\n", tp->core.pc);
		fprintf(fp, "        range: %ld\n", tp->core.range);
		fprintf(fp, "     init: pc: %lx\n", tp->init.pc);
		fprintf(fp, "        range: %ld\n", tp->init.range);
		fprintf(fp, "      address: %lx\n", (ulong)tp->address);
		fprintf(fp, "         size: %ld\n", tp->size);
	}
}


int 
dwarf_backtrace(struct bt_info *bt, int level, ulong stacktop)
{
	unsigned long bp, offset;
	struct syment *sp;
	char *name;
	struct unwind_frame_info *frame;
	int is_ehframe = (!st->dwarf_debug_frame_size && st->dwarf_eh_frame_size);

	frame = (struct unwind_frame_info *)GETBUF(sizeof(struct unwind_frame_info));
//	frame->regs.rsp = bt->stkptr;
//	frame->regs.rip = bt->instptr;
	UNW_SP(frame) = bt->stkptr;
	UNW_PC(frame) = bt->instptr;

	/* read rbp from stack for non active tasks */
	if (!(bt->flags & BT_DUMPFILE_SEARCH) && !bt->bptr) {
//		readmem(frame->regs.rsp, KVADDR, &bp,
		readmem(UNW_SP(frame), KVADDR, &bp,
	                sizeof(unsigned long), "reading bp", FAULT_ON_ERROR);
		frame->regs.rbp = bp;  /* fixme for x86 */
	}

	sp = value_search(UNW_PC(frame), &offset);
	if (!sp) {
		if (CRASHDEBUG(1))
		    fprintf(fp, "unwind: cannot find symbol for PC: %lx\n", 
			UNW_PC(frame));
		goto bailout;
	}

	/*
	 * If offset is zero, it means we have crossed over to the next
	 *  function. Recalculate by adjusting the text address
	 */
	if (!offset) {
		sp = value_search(UNW_PC(frame) - 1, &offset);
		if (!sp) {
			if (CRASHDEBUG(1))
				fprintf(fp, 
				    "unwind: cannot find symbol for PC: %lx\n",
					UNW_PC(frame)-1);
			goto bailout;
		}
	}
		


        name = sp->name;
	fprintf(fp, " #%d [%016lx] %s at %016lx \n", level, UNW_SP(frame), name, UNW_PC(frame));

	if (CRASHDEBUG(2))
		fprintf(fp, "    < SP: %lx PC: %lx FP: %lx >\n", UNW_SP(frame), 
			UNW_PC(frame), frame->regs.rbp);

       	while ((UNW_SP(frame) < stacktop)
				&& !unwind(frame, is_ehframe) && UNW_PC(frame)) {
		/* To prevent rip pushed on IRQ stack being reported both
		 * both on the IRQ and process stacks
		 */
		if ((bt->flags & BT_IRQSTACK) && (UNW_SP(frame) >= stacktop - 16))
			break;
               	level++;
		sp = value_search(UNW_PC(frame), &offset);
		if (!sp) {
			if (CRASHDEBUG(1))
				fprintf(fp, 
				    "unwind: cannot find symbol for PC: %lx\n",
					UNW_PC(frame));
			break;
		}

		/*
		 * If offset is zero, it means we have crossed over to the next
		 *  function. Recalculate by adjusting the text address
		 */
		if (!offset) {
			sp = value_search(UNW_PC(frame) - 1, &offset);
			if (!sp) {
				if (CRASHDEBUG(1))
					fprintf(fp,
					    "unwind: cannot find symbol for PC: %lx\n",
						UNW_PC(frame)-1);
				goto bailout;
			}
		}
	        name = sp->name;
		fprintf(fp, "%s#%d [%016lx] %s at %016lx \n", level < 10 ? " " : "",
			level, UNW_SP(frame), name, UNW_PC(frame));

		if (CRASHDEBUG(2))
			fprintf(fp, "    < SP: %lx PC: %lx FP: %lx >\n", UNW_SP(frame), 
				UNW_PC(frame), frame->regs.rbp);
       	}

bailout:
	FREEBUF(frame);
	return ++level;
}

int 
dwarf_print_stack_entry(struct bt_info *bt, int level)
{
	unsigned long offset;
	struct syment *sp;
	char *name;
	struct unwind_frame_info *frame;

	frame = (struct unwind_frame_info *)GETBUF(sizeof(struct unwind_frame_info));
	UNW_SP(frame) = bt->stkptr;
	UNW_PC(frame) = bt->instptr;

	sp = value_search(UNW_PC(frame), &offset);
	if (!sp) {
		if (CRASHDEBUG(1))
		    fprintf(fp, "unwind: cannot find symbol for PC: %lx\n",
			UNW_PC(frame));
		goto bailout;
	}

	/*
	 * If offset is zero, it means we have crossed over to the next
	 *  function. Recalculate by adjusting the text address
	 */
	if (!offset) {
		sp = value_search(UNW_PC(frame) - 1, &offset);
		if (!sp) {
			if (CRASHDEBUG(1))
				fprintf(fp,
				    "unwind: cannot find symbol for PC: %lx\n",
					UNW_PC(frame)-1);
			goto bailout;
		}
	}
        name = sp->name;
	fprintf(fp, " #%d [%016lx] %s at %016lx \n", level, UNW_SP(frame), name, UNW_PC(frame));

bailout:
	FREEBUF(frame);
	return level;
}

void
dwarf_debug(struct bt_info *bt)
{
	struct unwind_frame_info *frame;
	ulong bp;
	int is_ehframe = (!st->dwarf_debug_frame_size && st->dwarf_eh_frame_size);

	if (!bt->hp->eip) {
		dump_local_unwind_tables();
		return;
	}

	if (!(kt->flags & DWARF_UNWIND_CAPABLE)) {
		error(INFO, "not DWARF capable\n");
		return;
	}

        frame = (struct unwind_frame_info *)GETBUF(sizeof(struct unwind_frame_info));

	/*
	 *  XXX: This only works for the first PC/SP pair seen in a normal
	 *  backtrace, so it's not particularly helpful.  Ideally it should
         *  be capable to take any PC/SP pair in a stack, but it appears to
	 *  related to the rbp value. 
	 */

	UNW_PC(frame) = bt->hp->eip;
	UNW_SP(frame) = bt->hp->esp;

        readmem(UNW_SP(frame), KVADDR, &bp,
 		sizeof(unsigned long), "reading bp", FAULT_ON_ERROR);
        frame->regs.rbp = bp;  /* fixme for x86 */

	unwind(frame, is_ehframe);

	fprintf(fp, "frame size: %lx (%lx)\n", 
		(ulong)UNW_SP(frame), (ulong)UNW_SP(frame) - bt->hp->esp);

	FREEBUF(frame);
}


#endif 
