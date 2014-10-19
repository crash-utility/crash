#ifdef CRASH_MERGE
#include "gdb/defs.h"
#include "block.h"
#include "symtab.h"
#include "symfile.h"
#include "command.h"
#include "expression.h"
#include "objfiles.h"
#include "value.h"
#include "top.h"
#include "gdb-stabs.h"
#include "interps.h"
#include "version.h"
#define GDB_COMMON
#include "../../defs.h"
#include "../../crash.h"

static ulong gdb_merge_flags = 0;
#define KERNEL_SYMBOLS_PATCHED (0x1)

#undef STREQ
#define STREQ(A, B)      (A && B && (strcmp(A, B) == 0))
/*
 *  Given a PC value, return the file and line number.
 */
static void
gdb_get_line_number(struct gnu_request *req)
{
        struct symtab_and_line sal;
	struct symbol *sym;
        CORE_ADDR pc;

#define LASTCHAR(s)      (s[strlen(s)-1])

	/*
	 * Prime the addrmap pump.
	 */
	if (req->name)
		sym = lookup_symbol(req->name, 0, VAR_DOMAIN, 0);

        pc = req->addr;

        sal = find_pc_line(pc, 0);

	if (!sal.symtab) {
		req->buf[0] = '\0';
		return;
	}

        if (sal.symtab->filename && sal.symtab->dirname) {
                if (sal.symtab->filename[0] == '/')
                        sprintf(req->buf, "%s: %d",
                                sal.symtab->filename, sal.line);
                else
                        sprintf(req->buf, "%s%s%s: %d",
                                sal.symtab->dirname,
                                LASTCHAR(sal.symtab->dirname) == '/' ? "" : "/",
                                sal.symtab->filename, sal.line);
        }
}

/*
 *  Walk through a struct type's list of fields looking for the desired
 *  member field, and when found, return its relevant data.
 */
static void
get_member_data(struct gnu_request *req, struct type *type)
{
	register short i;
	struct field *nextfield;
	short nfields;
	struct type *typedef_type;

	req->member_offset = -1;

	nfields = TYPE_MAIN_TYPE(type)->nfields;
	nextfield = TYPE_MAIN_TYPE(type)->flds_bnds.fields;

        if (nfields == 0) {
		struct type *newtype;
                newtype = lookup_transparent_type(req->name);
                if (newtype) {
                        console("get_member_data(%s.%s): switching type from %lx to %lx\n",
				req->name, req->member, type, newtype);
                	nfields = TYPE_MAIN_TYPE(newtype)->nfields;
                	nextfield = TYPE_MAIN_TYPE(newtype)->flds_bnds.fields;
		}
        }

	for (i = 0; i < nfields; i++) {
		if (STREQ(req->member, nextfield->name)) {
			req->member_offset = nextfield->loc.bitpos;
			req->member_length = TYPE_LENGTH(nextfield->type);
			req->member_typecode = TYPE_CODE(nextfield->type);
			if ((req->member_typecode == TYPE_CODE_TYPEDEF) &&
			    (typedef_type = check_typedef(nextfield->type)))
        			req->member_length = TYPE_LENGTH(typedef_type);
			return;
		}
		nextfield++;
	}
}

/*
 *  More robust enum list dump that gdb's, showing the value of each
 *  identifier, each on its own line.
 */
static void
dump_enum(struct type *type, struct gnu_request *req)
{
	register int i;
	int len;
	long long lastval;

        len = TYPE_NFIELDS (type);
        lastval = 0;
	if (TYPE_TAG_NAME(type))
        	fprintf_filtered(gdb_stdout,
			"enum %s {\n", TYPE_TAG_NAME (type));
	else
		fprintf_filtered(gdb_stdout, "enum {\n");

        for (i = 0; i < len; i++) {
        	fprintf_filtered(gdb_stdout, "  %s",
			TYPE_FIELD_NAME (type, i));
                if (lastval != TYPE_FIELD_ENUMVAL (type, i)) {
                	fprintf_filtered (gdb_stdout, " = %s",
                        	plongest(TYPE_FIELD_ENUMVAL (type, i)));
                        lastval = TYPE_FIELD_ENUMVAL (type, i);
                } else
                        fprintf_filtered(gdb_stdout, " = %s", plongest(lastval));
                fprintf_filtered(gdb_stdout, "\n");
                lastval++;
        }
	if (TYPE_TAG_NAME(type))
		fprintf_filtered(gdb_stdout, "};\n");
	else
		fprintf_filtered(gdb_stdout, "} %s;\n", req->name);
}

/*
 *  Given an enum type with no tagname, determine its value.
 */
static void
eval_enum(struct type *type, struct gnu_request *req)
{
        register int i;
        int len;
        int lastval;

        len = TYPE_NFIELDS (type);
        lastval = 0;

        for (i = 0; i < len; i++) {
                if (lastval != TYPE_FIELD_BITPOS (type, i)) {
                        lastval = TYPE_FIELD_BITPOS (type, i);
                }
		if (STREQ(TYPE_FIELD_NAME(type, i), req->name)) {
			req->tagname = "(unknown)";
			req->value = lastval;
			return;
		}
                lastval++;
        }
}

/*
 *  General purpose routine for determining datatypes.
 */
static void
gdb_get_datatype(struct gnu_request *req)
{
 	register struct cleanup *old_chain = NULL;
  	register struct type *type;
	register struct type *typedef_type;
  	struct expression *expr;
	struct symbol *sym;
        register int i;
        struct field *nextfield;
	struct value *val;

	if (gdb_CRASHDEBUG(2))
		console("gdb_get_datatype [%s] (a)\n", req->name);

	req->typecode = TYPE_CODE_UNDEF;

	/*
	 *  lookup_symbol() will pick up struct and union names.
	 */
	sym = lookup_symbol(req->name, 0, STRUCT_DOMAIN, 0);
	if (sym) {
                req->typecode = TYPE_CODE(sym->type);
                req->length = TYPE_LENGTH(sym->type);
		if (req->member)
			get_member_data(req, sym->type);

		if (TYPE_CODE(sym->type) == TYPE_CODE_ENUM) {
			if (req->flags & GNU_PRINT_ENUMERATORS)
				dump_enum(sym->type, req);
		}

		return;
	}

	/*
	 *  Otherwise parse the expression.
	 */
	if (gdb_CRASHDEBUG(2))
		console("gdb_get_datatype [%s] (b)\n", req->name);

        expr = parse_expression(req->name);

        old_chain = make_cleanup(free_current_contents, &expr);


	switch (expr->elts[0].opcode)
	{
	case OP_VAR_VALUE:
		if (gdb_CRASHDEBUG(2))
        		console("expr->elts[0].opcode: OP_VAR_VALUE\n");
		type = expr->elts[2].symbol->type;
		if (req->flags & GNU_VAR_LENGTH_TYPECODE) {
			req->typecode = TYPE_CODE(type);
			req->length = TYPE_LENGTH(type);
		}
		if (TYPE_CODE(type) == TYPE_CODE_ENUM) {
			req->typecode = TYPE_CODE(type);
			req->value = SYMBOL_VALUE(expr->elts[2].symbol);
			req->tagname = (char *)TYPE_TAG_NAME(type);
			if (!req->tagname) {
				val = evaluate_type(expr);
				eval_enum(value_type(val), req);
			}
		}
		break;

  	case OP_TYPE:
		if (gdb_CRASHDEBUG(2))
        		console("expr->elts[0].opcode: OP_TYPE\n");
    		type = expr->elts[1].type;

		req->typecode = TYPE_CODE(type);
		req->length = TYPE_LENGTH(type);

        	if (TYPE_CODE(type) == TYPE_CODE_TYPEDEF) {
			req->is_typedef = TYPE_CODE_TYPEDEF;
                	if ((typedef_type = check_typedef(type))) {
                        	req->typecode = TYPE_CODE(typedef_type);
                        	req->length = TYPE_LENGTH(typedef_type);
				type = typedef_type;
			}
		}

                if (TYPE_CODE(type) == TYPE_CODE_ENUM) {
			if (req->is_typedef)
                        if (req->flags & GNU_PRINT_ENUMERATORS) {
				if (req->is_typedef)
					fprintf_filtered(gdb_stdout,
						"typedef ");
                                dump_enum(type, req);
			}
		}

                if (req->member)
                	get_member_data(req, type);

		break;

	default:
		if (gdb_CRASHDEBUG(2))
			console("expr->elts[0].opcode: %d (?)\n",
				expr->elts[0].opcode);
		break;

	}

        do_cleanups(old_chain);
}

/*
 *  Check whether a command exists.  If it doesn't, the command will be
 *  returned indirectly via the error_hook.
 */
static void
gdb_command_exists(struct gnu_request *req)
{
        extern struct cmd_list_element *cmdlist;
        register struct cmd_list_element *c;

        req->value = FALSE;
        c = lookup_cmd(&req->name, cmdlist, "", 0, 1);
        req->value = TRUE;
}

static void
gdb_function_numargs(struct gnu_request *req)
{
        struct symbol *sym;

        sym = find_pc_function(req->pc);

        if (!sym || TYPE_CODE(sym->type) != TYPE_CODE_FUNC) {
                req->flags |= GNU_COMMAND_FAILED;
                return;
        }

	req->value = (ulong)TYPE_NFIELDS(sym->type);
}

struct load_module *gdb_current_load_module = NULL;

static void
gdb_delete_symbol_file(struct gnu_request *req)
{
        register struct objfile *objfile;

        ALL_OBJFILES(objfile) {
                if (STREQ(objfile->name, req->name) ||
		    same_file(objfile->name, req->name)) {
                	free_objfile(objfile);
			break;
                }
        }

	if (gdb_CRASHDEBUG(2)) {
		fprintf_filtered(gdb_stdout, "current object files:\n");
		ALL_OBJFILES(objfile)
			fprintf_filtered(gdb_stdout, "  %s\n", objfile->name);
	}
}

static void
gdb_add_symbol_file(struct gnu_request *req)
{
	register struct objfile *loaded_objfile = NULL;
	register struct objfile *objfile;
	register struct minimal_symbol *m;
	struct load_module *lm;
	int external, subsequent, found;
	off_t offset;
	ulong value, adjusted;
	struct symbol *sym;
	struct expression *expr;
	struct cleanup *old_chain;
	int i;
        int allsect = 0;
        char *secname;
        char buf[80];

	gdb_current_load_module = lm = (struct load_module *)req->addr;

	req->name = lm->mod_namelist;
	gdb_delete_symbol_file(req);

	if ((lm->mod_flags & MOD_NOPATCH) == 0) {
	        for (i = 0 ; i < lm->mod_sections; i++) {
	            if (STREQ(lm->mod_section_data[i].name, ".text") &&
	                (lm->mod_section_data[i].flags & SEC_FOUND))
	                    allsect = 1;
	        }

	        if (!allsect) {
	            sprintf(req->buf, "add-symbol-file %s 0x%lx %s", lm->mod_namelist,
	                    lm->mod_text_start ? lm->mod_text_start : lm->mod_base,
			    lm->mod_flags & MOD_DO_READNOW ? "-readnow" : "");
		    if (lm->mod_data_start) {
	                    sprintf(buf, " -s .data 0x%lx", lm->mod_data_start);
	                    strcat(req->buf, buf);
		    }
		    if (lm->mod_bss_start) {
	                    sprintf(buf, " -s .bss 0x%lx", lm->mod_bss_start);
	                    strcat(req->buf, buf);
		    }
		    if (lm->mod_rodata_start) {
	                    sprintf(buf, " -s .rodata 0x%lx", lm->mod_rodata_start);
	                    strcat(req->buf, buf);
		    }
	        } else {
	            sprintf(req->buf, "add-symbol-file %s 0x%lx %s", lm->mod_namelist,
	                    lm->mod_text_start, lm->mod_flags & MOD_DO_READNOW ?
			    "-readnow" : "");
	            for (i = 0; i < lm->mod_sections; i++) {
	                    secname = lm->mod_section_data[i].name;
	                    if ((lm->mod_section_data[i].flags & SEC_FOUND) &&
	                        !STREQ(secname, ".text")) {
	                            sprintf(buf, " -s %s 0x%lx", secname,
	                                lm->mod_section_data[i].offset + lm->mod_base);
	                            strcat(req->buf, buf);
	                    }
	            }
	        }
	}

	if (gdb_CRASHDEBUG(1))
            fprintf_filtered(gdb_stdout, "%s\n", req->buf);

       	execute_command(req->buf, FALSE);

        ALL_OBJFILES(objfile) {
		if (same_file(objfile->name, lm->mod_namelist)) {
                        loaded_objfile = objfile;
			break;
		}
        }

	if (!loaded_objfile)
                req->flags |= GNU_COMMAND_FAILED;
}


/*
 *  Walk through all minimal_symbols, patching their values with the
 *  correct addresses.
 */
static void
gdb_patch_symbol_values(struct gnu_request *req)
{
	struct minimal_symbol *msymbol;
	struct objfile *objfile;

	req->name = PATCH_KERNEL_SYMBOLS_START;
	patch_kernel_symbol(req, NULL);

	ALL_MSYMBOLS (objfile, msymbol)
	{
		req->name = (char *)msymbol->ginfo.name;
		if (!patch_kernel_symbol(req, msymbol)) {
			req->flags |= GNU_COMMAND_FAILED;
			break;
		}
	}

	req->name = PATCH_KERNEL_SYMBOLS_STOP;
	patch_kernel_symbol(req, NULL);

	clear_symtab_users(0);
	gdb_merge_flags |= KERNEL_SYMBOLS_PATCHED;
}

extern void gdb_patch_minsymbol_address(struct minimal_symbol *msym,
				        unsigned long addr);
void gdb_patch_minsymbol_address(struct minimal_symbol *msym,
				 unsigned long addr)
{
	SYMBOL_VALUE_ADDRESS(msym) = addr;
}

static void
gdb_get_symbol_type(struct gnu_request *req)
{
        struct expression *expr;
        struct value *val;
        struct cleanup *old_chain = NULL;
        struct type *type;
	struct type *target_type;

	req->typecode = TYPE_CODE_UNDEF;

        expr = parse_expression (req->name);
        old_chain = make_cleanup (free_current_contents, &expr);
        val = evaluate_type (expr);

        type = value_type(val);

	req->type_name = (char *)TYPE_MAIN_TYPE(type)->name;
	req->typecode = TYPE_MAIN_TYPE(type)->code;
	req->length = type->length;
	target_type = TYPE_MAIN_TYPE(type)->target_type;

	if (target_type) {
		req->target_typename = (char *)TYPE_MAIN_TYPE(target_type)->name;
		req->target_typecode = TYPE_MAIN_TYPE(target_type)->code;
		req->target_length = target_type->length;
	}

	if (req->member)
		get_member_data(req, type);

        do_cleanups (old_chain);
}

static void
gdb_debug_command(struct gnu_request *req)
{

}

/*
 *  Only necessary on "patched" kernel symbol sessions, and called only by
 *  lookup_symbol(), pull a symbol value bait-and-switch operation by altering
 *  either a data symbol's address value or a text symbol's block start address.
 */
void
gdb_bait_and_switch(char *name, struct symbol *sym)
{
	struct minimal_symbol *msym;
	struct block *block;

	if (!(gdb_merge_flags & KERNEL_SYMBOLS_PATCHED))
		return;

	msym = lookup_minimal_symbol(name, NULL, symfile_objfile);
	if (!msym)
		return;

	if (sym->aclass == LOC_BLOCK) {
		block = (struct block *)SYMBOL_BLOCK_VALUE(sym);
		BLOCK_START(block) = SYMBOL_VALUE_ADDRESS(msym);
	} else
		SYMBOL_VALUE_ADDRESS(sym) = SYMBOL_VALUE_ADDRESS(msym);
}

#include "valprint.h"

static void
get_user_print_option_address(struct gnu_request *req)
{
	extern struct value_print_options user_print_options;

	req->addr = 0;

        if (strcmp(req->name, "output_format") == 0)
                req->addr = (ulong)&user_print_options.output_format;
        if (strcmp(req->name, "print_max") == 0)
                req->addr = (ulong)&user_print_options.print_max;
        if (strcmp(req->name, "prettyprint_structs") == 0)
                req->addr = (ulong)&user_print_options.prettyprint_structs;
        if (strcmp(req->name, "prettyprint_arrays") == 0)
                req->addr = (ulong)&user_print_options.prettyprint_arrays;
        if (strcmp(req->name, "repeat_count_threshold") == 0)
                req->addr = (ulong)&user_print_options.repeat_count_threshold;
        if (strcmp(req->name, "stop_print_at_null") == 0)
                req->addr = (ulong)&user_print_options.stop_print_at_null;
        if (strcmp(req->name, "output_radix") == 0)
                req->addr = (ulong)&output_radix;
}

CORE_ADDR crash_text_scope;

static void
gdb_set_crash_block(struct gnu_request *req)
{
	if (!req->addr) {  /* debug */
		crash_text_scope = 0;
		return;
	}

	if ((req->addr2 = (ulong)block_for_pc(req->addr)))
		crash_text_scope = req->addr;
	else {
		crash_text_scope = 0;
		req->flags |= GNU_COMMAND_FAILED;
	}
}

struct block *
gdb_get_crash_block(void)
{
	if (crash_text_scope)
		return block_for_pc(crash_text_scope);
	else
		return NULL;
}

/*
 *  All commands from above come through here.
 */
void
gdb_command_funnel(struct gnu_request *req)
{
        struct symbol *sym;

	if (req->command != GNU_VERSION) {
        	replace_ui_file_FILE(gdb_stdout, req->fp);
        	replace_ui_file_FILE(gdb_stderr, req->fp);
		do_cleanups(all_cleanups());
	}

	switch (req->command)
	{
	case GNU_VERSION:
		req->buf = (char *)version;
		break;

        case GNU_PASS_THROUGH:
                execute_command(req->buf,
			req->flags & GNU_FROM_TTY_OFF ? FALSE : TRUE);
		break;

	case GNU_USER_PRINT_OPTION:
		get_user_print_option_address(req);
		break;

	case GNU_RESOLVE_TEXT_ADDR:
                sym = find_pc_function(req->addr);
                if (!sym || TYPE_CODE(sym->type) != TYPE_CODE_FUNC)
                        req->flags |= GNU_COMMAND_FAILED;
		break;

        case GNU_DISASSEMBLE:
		if (req->addr2)
                	sprintf(req->buf, "disassemble 0x%lx 0x%lx",
				req->addr, req->addr2);
		else
                	sprintf(req->buf, "disassemble 0x%lx", req->addr);
                execute_command(req->buf, TRUE);
                break;

	case GNU_ADD_SYMBOL_FILE:
		gdb_add_symbol_file(req);
		break;

	case GNU_DELETE_SYMBOL_FILE:
		gdb_delete_symbol_file(req);
		break;

	case GNU_GET_LINE_NUMBER:
		gdb_get_line_number(req);
		break;

	case GNU_GET_DATATYPE:
		gdb_get_datatype(req);
		break;

	case GNU_GET_SYMBOL_TYPE:
		gdb_get_symbol_type(req);
		break;

	case GNU_COMMAND_EXISTS:
		gdb_command_exists(req);
		break;

	case GNU_ALPHA_FRAME_OFFSET:
		req->value = 0;
		break;

	case GNU_FUNCTION_NUMARGS:
		gdb_function_numargs(req);
		break;

	case GNU_DEBUG_COMMAND:
		gdb_debug_command(req);
		break;

	case GNU_PATCH_SYMBOL_VALUES:
		gdb_patch_symbol_values(req);
		break;

	case GNU_SET_CRASH_BLOCK:
		gdb_set_crash_block(req);
		break;

	default:
		req->flags |= GNU_COMMAND_FAILED;
		break;
	}
}

extern initialize_file_ftype _initialize_crash_interp;
extern void main_loop(void *);

/*
 * initialized by _initialize_cli_interp. This obviously depends on
 * _initialize_cli_interp running prior to _initialize_crash_interp.
 */
const struct interp_procs *cli_procs;
void
_initialize_crash_interp (void)
{
	struct interp *command_interp, *cli_interp;
	static struct interp_procs crash_procs;
	crash_procs.init_proc    = cli_procs->init_proc;
	crash_procs.resume_proc  = cli_procs->resume_proc;
	crash_procs.suspend_proc = cli_procs->suspend_proc;
	crash_procs.exec_proc    = cli_procs->exec_proc;
	crash_procs.ui_out_proc  = cli_procs->ui_out_proc;
	crash_procs.set_logging_proc = cli_procs->set_logging_proc;
	crash_procs.command_loop_proc = main_loop;

	command_interp = interp_new("crash-command", &crash_procs);

	interp_add(command_interp);
}
#endif
