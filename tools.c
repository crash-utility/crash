/* tools.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2019 David Anderson
 * Copyright (C) 2002-2019 Red Hat, Inc. All rights reserved.
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
#include <ctype.h>

#ifdef VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#endif

static void print_number(struct number_option *, int, int);
static long alloc_hq_entry(void);
struct hq_entry;
static void dealloc_hq_entry(struct hq_entry *);
static void show_options(void);
static void dump_struct_members(struct list_data *, int, ulong);
static void rbtree_iteration(ulong, struct tree_data *, char *);
void dump_struct_members_for_tree(struct tree_data *, int, ulong);

struct req_entry {
	char *arg, *name, **member;
	int *is_str, *is_ptr;
	ulong *width, *offset;
	int count;
};

static void print_value(struct req_entry *, unsigned int, ulong, unsigned int);
struct req_entry *fill_member_offsets(char *);
void dump_struct_members_fast(struct req_entry *, int, ulong);

FILE *
set_error(char *target)
{
	FILE *tmp_fp = NULL;
	char *tmp_str = NULL;

	if (STREQ(target, pc->error_path))
		return pc->error_fp;

	tmp_str = malloc(strlen(target) + 1);
	if (tmp_str == NULL)
		return NULL;
	strcpy(tmp_str, target);

	if (STREQ(target, "default"))
		tmp_fp = stdout;
	else if (STREQ(target, "redirect"))
		tmp_fp = fp;
	else {
		tmp_fp = fopen(target, "a");
		if (tmp_fp == NULL) {
			error(INFO, "invalid path: %s\n", target);
			return NULL;
		}
	}

	if (pc->error_fp != NULL && pc->error_fp != stdout && pc->error_fp != fp)
		fclose(pc->error_fp);
	if (pc->error_path)
		free(pc->error_path);

	pc->error_fp = tmp_fp;
	pc->error_path = tmp_str;

	return pc->error_fp;
}


/*
 *  General purpose error reporting routine.  Type INFO prints the message
 *  and returns.  Type FATAL aborts the command in progress, and longjmps
 *  back to the appropriate recovery location.  If a FATAL occurs during 
 *  program initialization, exit() is called.
 *
 *  The idea is to get the message out so that it is seen by the user
 *  regardless of how the command output may be piped or redirected.
 *  Besides stderr, check whether the output is going to a file or pipe, and
 *  if so, intermingle the error message there as well.
 */
int
__error(int type, char *fmt, ...)
{
	int end_of_line, new_line;
        char buf[BUFSIZE];
	char *spacebuf;
        void *retaddr[NUMBER_STACKFRAMES] = { 0 };
	va_list ap;

	if (STREQ(pc->error_path, "redirect"))
		pc->error_fp = fp;

	if (CRASHDEBUG(1) || (pc->flags & DROP_CORE)) {
		SAVE_RETURN_ADDRESS(retaddr);
		console("error() trace: %lx => %lx => %lx => %lx\n",
			retaddr[3], retaddr[2], retaddr[1], retaddr[0]);
	}

	va_start(ap, fmt);
	(void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

	if (!fmt && FATAL_ERROR(type)) {
		fprintf(pc->error_fp, "\n");
		clean_exit(1);
	}

	end_of_line = FATAL_ERROR(type) && !(pc->flags & RUNTIME);

	if ((new_line = (buf[0] == '\n')))
		shift_string_left(buf, 1);
	else if (pc->flags & PLEASE_WAIT)
		new_line = TRUE;

	if (type == CONT)
		spacebuf = space(strlen(pc->curcmd));
	else
		spacebuf = NULL;

	if (pc->stdpipe && 
	    (STREQ(pc->error_path, "default") || STREQ(pc->error_path, "redirect"))) {
		fprintf(pc->stdpipe, "%s%s%s %s%s", 
			new_line ? "\n" : "", 
			type == CONT ? spacebuf : pc->curcmd, 
			type == CONT ? " " : ":",
			type == WARNING ? "WARNING: " : 
			type == NOTE ? "NOTE: " : "", 
			buf);
		fflush(pc->stdpipe);
	} else { 
		fprintf(pc->error_fp, "%s%s%s %s%s",
			new_line || end_of_line ? "\n" : "",
			type == WARNING ? "WARNING" : 
			type == NOTE ? "NOTE" : 
			type == CONT ? spacebuf : pc->curcmd,
			type == CONT ? " " : ":",
			buf, end_of_line ? "\n" : "");
		fflush(pc->error_fp);
	}

	if ((STREQ(pc->error_path, "default")) &&
	    (fp != stdout) && (fp != pc->stdpipe) && (fp != pc->tmpfile)) {
		fprintf(fp, "%s%s%s %s", new_line ? "\n" : "",
			type == WARNING ? "WARNING" :
			type == NOTE ? "NOTE" :
			type == CONT ? spacebuf : pc->curcmd,
			type == CONT ? " " : ":",
			buf);
		fflush(fp);
	}

	if ((pc->flags & DROP_CORE) && (type != NOTE)) {
		dump_trace(retaddr);
		SIGACTION(SIGSEGV, SIG_DFL, &pc->sigaction, NULL);
		drop_core("DROP_CORE flag set: forcing a segmentation fault\n");
	}

        switch (type)
        {
        case FATAL:
                if (pc->flags & IN_FOREACH) 
                        RESUME_FOREACH();
		/* FALLTHROUGH */

	case FATAL_RESTART:
                if (pc->flags & RUNTIME) 
                        RESTART();
                else {
			if (REMOTE())
				remote_exit();
                        clean_exit(1);
		}

	default:
        case INFO:
        case NOTE:
	case WARNING:
                return FALSE;
        }
}

/*
 *  Parse a line into tokens, populate the passed-in argv[] array, and return
 *  the count of arguments found.  This function modifies the passed-string 
 *  by inserting a NULL character at the end of each token.  Expressions 
 *  encompassed by parentheses, and strings encompassed by apostrophes, are 
 *  collected into single tokens.
 */
int
parse_line(char *str, char *argv[])
{
	int i, j, k;
    	int string;
	int expression;

	for (i = 0; i < MAXARGS; i++)
		argv[i] = NULL;

	clean_line(str);

        if (str == NULL || strlen(str) == 0)
                return(0);

        i = j = k = 0;
        string = FALSE;
	expression = 0;

	/*
	 * Special handling for when the first character is a '"'.
	 */
	if (str[0] == '"') {
next:
		do {
			i++;
		} while ((str[i] != NULLCHAR) && (str[i] != '"'));

		switch (str[i])
		{
		case NULLCHAR:
			argv[j] = &str[k];
			return j+1;
		case '"':
			argv[j++] = &str[k+1];
			str[i++] = NULLCHAR;
			if (str[i] == '"') {
				k = i;
				goto next;	
			}
			break;
		}
	} else
		argv[j++] = str;

    	while (TRUE) {
		if (j == MAXARGS)
			error(FATAL, "too many arguments in string!\n");

        	while (str[i] != ' ' && str[i] != '\t' && str[i] != NULLCHAR) {
            		i++;
        	}

	        switch (str[i])
	        {
	        case ' ':
	        case '\t':
	            str[i++] = NULLCHAR;

	            while (str[i] == ' ' || str[i] == '\t') {
	                i++;
	            }
	
	            if (str[i] == '"') {    
	                str[i] = ' ';
	                string = TRUE;
	                i++;
	            }

		    /*
		     *  Make an expression encompassed by a set of parentheses 
		     *  a single argument.  Also account for embedded sets.
		     */
		    if (!string && str[i] == '(') {     
			argv[j++] = &str[i];
			expression = 1;
			while (expression > 0) {
				i++;
				switch (str[i])
				{
				case '(':
					expression++;
					break;
				case ')':
					expression--;
					break;
				case NULLCHAR:
				case '\n':
					expression = -1;
					break;
				default:
					break;
				}
			}
			if (expression == 0) {
				i++;
				continue;
			}
		    }

	            if (str[i] != NULLCHAR && str[i] != '\n') {
	                argv[j++] = &str[i];
	                if (string) {
	                        string = FALSE;
	                        while (str[i] != '"' && str[i] != NULLCHAR)
	                                i++;
	                        if (str[i] == '"')
	                                str[i] = ' ';
	                }
	                break;
	            }
	                        /* else fall through */
	        case '\n':
	            str[i] = NULLCHAR;
	                        /* keep falling... */
	        case NULLCHAR:
	            argv[j] = NULLCHAR;
	            return(j);
	        }
    	}  
}

/*
 *  Defuse controversy re: extensions to ctype.h 
 */
int 
whitespace(int c)
{
	return ((c == ' ') ||(c == '\t'));
}

int
ascii(int c)
{
	return ((c >= 0) && ( c <= 0x7f));
}

/*
 *  Strip line-ending whitespace and linefeeds.
 */
char *
strip_line_end(char *line)
{
	strip_linefeeds(line);
	strip_ending_whitespace(line);
	return(line);
}

/*
 *  Strip line-beginning and line-ending whitespace and linefeeds.
 */
char *
clean_line(char *line)
{
	strip_beginning_whitespace(line);
        strip_linefeeds(line);
        strip_ending_whitespace(line);
        return(line);
}

/*
 *  Strip line-ending linefeeds in a string.
 */
char *
strip_linefeeds(char *line)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	while (*p == '\n') {
		*p = NULLCHAR;
		if (--p < line)
			break; 
	}

	return(line);
}

/*
 *  Strip a specified line-ending character in a string.
 */
char *
strip_ending_char(char *line, char c)
{
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        if (*p == c)
                *p = NULLCHAR;

        return(line);
}

/*
 *  Strip a specified line-beginning character in a string.
 */
char *
strip_beginning_char(char *line, char c)
{
        if (line == NULL || strlen(line) == 0)
                return(line);

        if (FIRSTCHAR(line) == c)
                shift_string_left(line, 1);

        return(line);
}




/*
 *  Strip line-ending whitespace.
 */
char *
strip_ending_whitespace(char *line)
{
        char *p;

	if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        while (*p == ' ' || *p == '\t') {
                *p = NULLCHAR;
                if (p == line)
                        break;
                p--;
        }

        return(line);
}

/*
 *  Strip line-beginning whitespace.
 */
char *
strip_beginning_whitespace(char *line)
{
	char buf[BUFSIZE];
        char *p;

	if (line == NULL || strlen(line) == 0)
                return(line);

	strcpy(buf, line);
	p = &buf[0];
	while (*p == ' ' || *p == '\t')
		p++;
	strcpy(line, p);

        return(line);
}

/*
 *  End line at first comma found.
 */
char *
strip_comma(char *line)
{
	char *p;

	if ((p = strstr(line, ",")))
		*p = NULLCHAR;

	return(line);
}

/*
 *  Strip the 0x from the beginning of a hexadecimal value string.
 */
char *
strip_hex(char *line)
{
	if (STRNEQ(line, "0x")) 
		shift_string_left(line, 2);	

	return(line);
}

/*
 *  Turn a string into upper-case.
 */
char *
upper_case(const char *s, char *buf)
{
	const char *p1;
	char *p2;

	p1 = s;
	p2 = buf;

	while (*p1) {
		*p2 = toupper(*p1);
		p1++, p2++;	
	}

	*p2 = NULLCHAR;

	return(buf);
}

/*
 *  Return pointer to first non-space/tab in a string.
 */
char *
first_nonspace(char *s)
{
        return(s + strspn(s, " \t"));
}

/*
 *  Return pointer to first space/tab in a string.  If none are found,
 *  return a pointer to the string terminating NULL.
 */
char *
first_space(char *s)
{
        return(s + strcspn(s, " \t"));
}

/*
 *  Replace the first space/tab found in a string with a NULL character.
 */
char *
null_first_space(char *s)
{
	char *p1;

	p1 = first_space(s);
	if (*p1)
		*p1 = NULLCHAR;

	return s;
}

/*
 *  Replace any instances of the characters in string c that are found in
 *  string s with the character passed in r.
 */
char *
replace_string(char *s, char *c, char r)
{
	int i, j;

	for (i = 0; s[i]; i++) {
		for (j = 0; c[j]; j++) {
			if (s[i] == c[j])
				s[i] = r;
		}
	}

	return s;
}

void
string_insert(char *insert, char *where)
{
	char *p;

	p = GETBUF(strlen(insert) + strlen(where) + 1);
	sprintf(p, "%s%s", insert, where);
	strcpy(where, p);
	FREEBUF(p);
}

/*
 *  Find the rightmost instance of a substring in a string.
 */
char *
strstr_rightmost(char *s, char *lookfor)
{
	char *next, *last, *p;

	for (p = s, last = NULL; *p; p++) {
		if (!(next = strstr(p, lookfor)))
			break;
		last = p = next;
	}

	return last;
}

/*
 *  Prints a string verbatim, allowing strings with % signs to be displayed
 *  without printf conversions.
 */
void
print_verbatim(FILE *filep, char *line)
{
	int i;

        for (i = 0; i < strlen(line); i++) {
                fputc(line[i], filep);
		fflush(filep);
	}
}

char *
fixup_percent(char *s)
{
	char *p1;

	if ((p1 = strstr(s, "%")) == NULL)
		return s;

	s[strlen(s)+1] = NULLCHAR;
       	memmove(p1+1, p1, strlen(p1));
	*p1 = '%';

	return s;
}

/*
 *  Convert an indeterminate number string to either a hexadecimal or decimal 
 *  long value.  Translate with a bias towards decimal unless HEX_BIAS is set.
 */
ulong
stol(char *s, int flags, int *errptr)
{
	if ((flags & HEX_BIAS) && hexadecimal(s, 0)) 
        	return(htol(s, flags, errptr));
	else {
        	if (decimal(s, 0))
                	return(dtol(s, flags, errptr));
        	else if (hexadecimal(s, 0))
                	return(htol(s, flags, errptr));
	}

	if (!(flags & QUIET))
        	error(INFO, "not a valid number: %s\n", s);

        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
               	RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
        }

	return UNUSED;
}

ulonglong
stoll(char *s, int flags, int *errptr)
{
        if ((flags & HEX_BIAS) && hexadecimal(s, 0))
                return(htoll(s, flags, errptr));
        else {
                if (decimal(s, 0))
                        return(dtoll(s, flags, errptr));
                else if (hexadecimal(s, 0))
                        return(htoll(s, flags, errptr));
        }
 
	if (!(flags & QUIET))
        	error(INFO, "not a valid number: %s\n", s);

        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
                if (errptr)
                        *errptr = TRUE;
                break;
        }

        return UNUSED;
}

/*
 *  Append a two-character string to a number to make 1, 2, 3 and 4 into 
 *  1st, 2nd, 3rd, 4th, and so on...
 */
char *
ordinal(ulong val, char *buf)
{
	char *p1;
	
	sprintf(buf, "%ld", val);
	p1 = &buf[strlen(buf)-1];

	switch (*p1)
	{
	case '1':
		strcat(buf, "st");
		break;
	case '2':
		strcat(buf, "nd");
		break;
	case '3':
		strcat(buf, "rd");
		break;
	default:
		strcat(buf, "th");
		break;
	}

	return buf;
}

/*
 *  Convert a string into:
 *
 *   1.  an evaluated expression if it's enclosed within parentheses.
 *   2.  to a decimal value if the string is all decimal characters.
 *   3.  to a hexadecimal value if the string is all hexadecimal characters.
 *   4.  to a symbol value if the string is a known symbol.
 *
 *  If HEX_BIAS is set, pass the value on to htol().
 */
ulong
convert(char *s, int flags, int *errptr, ulong numflag)
{
	struct syment *sp;

	if ((numflag & NUM_EXPR) && can_eval(s))
             	return(eval(s, flags, errptr));

	if ((flags & HEX_BIAS) && (numflag & NUM_HEX) && hexadecimal(s, 0))
                return(htol(s, flags, errptr));
	else {
		if ((numflag & NUM_DEC) && decimal(s, 0))
	        	return(dtol(s, flags, errptr));
		if ((numflag & NUM_HEX) && hexadecimal(s, 0))
	        	return(htol(s, flags, errptr));
	}
	
	if ((sp = symbol_search(s)))
		return(sp->value);

        error(INFO, "cannot convert \"%s\"\n", s);

        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
                if (errptr)
                	*errptr = TRUE;
		break;
        }

        return UNUSED;
}

/*
 *  Convert a string to a hexadecimal long value.
 */
ulong
htol(char *s, int flags, int *errptr)
{
    	long i, j; 
	ulong n;

    	if (s == NULL) { 
		if (!(flags & QUIET))
			error(INFO, "received NULL string\n");
		goto htol_error;
	}

    	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
		s += 2;

    	if (strlen(s) > MAX_HEXADDR_STRLEN) { 
		if (!(flags & QUIET))
			error(INFO, 
			    "input string too large: \"%s\" (%d vs %d)\n", 
				s, strlen(s), MAX_HEXADDR_STRLEN);
		goto htol_error;
	}

    	for (n = i = 0; s[i] != 0; i++) {
	        switch (s[i]) 
	        {
	            case 'a':
	            case 'b':
	            case 'c':
	            case 'd':
	            case 'e':
	            case 'f':
	                j = (s[i] - 'a') + 10;
	                break;
	            case 'A':
	            case 'B':
	            case 'C':
	            case 'D':
	            case 'E':
	            case 'F':
	                j = (s[i] - 'A') + 10;
	                break;
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
	            case '0':
	                j = s[i] - '0';
	                break;
		    case 'x':
		    case 'X':
		    case 'h':
			continue;
	            default:
			if (!(flags & QUIET))
				error(INFO, "invalid input: \"%s\"\n", s);
			goto htol_error;
	        }
	        n = (16 * n) + j;
    	}

    	return(n);

htol_error:
	switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	{
	case FAULT_ON_ERROR:
		RESTART();

	case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
	}

	return BADADDR;
}

/*
 *  Convert a string to a hexadecimal unsigned long long value.
 */
ulonglong
htoll(char *s, int flags, int *errptr)
{
    	long i, j; 
	ulonglong n;

    	if (s == NULL) { 
		if (!(flags & QUIET))
			error(INFO, "received NULL string\n");
		goto htoll_error;
	}

    	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
		s += 2;

    	if (strlen(s) > LONG_LONG_PRLEN) { 
		if (!(flags & QUIET))
			error(INFO, 
			    "input string too large: \"%s\" (%d vs %d)\n", 
				s, strlen(s), LONG_LONG_PRLEN);
		goto htoll_error;
	}

    	for (n = i = 0; s[i] != 0; i++) {
	        switch (s[i]) 
	        {
	            case 'a':
	            case 'b':
	            case 'c':
	            case 'd':
	            case 'e':
	            case 'f':
	                j = (s[i] - 'a') + 10;
	                break;
	            case 'A':
	            case 'B':
	            case 'C':
	            case 'D':
	            case 'E':
	            case 'F':
	                j = (s[i] - 'A') + 10;
	                break;
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
	            case '0':
	                j = s[i] - '0';
	                break;
		    case 'x':
		    case 'X':
		    case 'h':
			continue;
	            default:
			if (!(flags & QUIET))
				error(INFO, "invalid input: \"%s\"\n", s);
			goto htoll_error;
	        }
	        n = (16 * n) + j;
    	}

    	return(n);

htoll_error:
	switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	{
	case FAULT_ON_ERROR:
		RESTART();

	case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
	}

	return UNUSED;
}


/*
 *  Convert a string to a decimal long value.
 */
ulong
dtol(char *s, int flags, int *errptr)
{
        ulong retval;
        char *p, *orig;
        int j;

        if (s == NULL) {
		if (!(flags & QUIET))
                	error(INFO, "received NULL string\n");
                goto dtol_error;
        }

	if (strlen(s) == 0)
                goto dtol_error;

        p = orig = &s[0];
        while (*p++ == ' ')
                s++;

        for (j = 0; s[j] != '\0'; j++)
                if ((s[j] < '0' || s[j] > '9'))
                        break ;

	if (s[j] != '\0') {
		if (!(flags & QUIET))
                	error(INFO, "%s: \"%c\" is not a digit 0 - 9\n", 
				orig, s[j]);
                goto dtol_error;
	} else if (sscanf(s, "%lu", &retval) != 1) {
		if (!(flags & QUIET))
                	error(INFO, "invalid expression\n");
                goto dtol_error;
        }

        return(retval);

dtol_error:
        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
                break;
        }

	return UNUSED;
}


/*
 *  Convert a string to a decimal long value.
 */
ulonglong
dtoll(char *s, int flags, int *errptr)
{
        ulonglong retval;
        char *p, *orig;
        int j;

        if (s == NULL) {
		if (!(flags & QUIET))
                	error(INFO, "received NULL string\n");
                goto dtoll_error;
        }

	if (strlen(s) == 0)
                goto dtoll_error;

        p = orig = &s[0];
        while (*p++ == ' ')
                s++;

        for (j = 0; s[j] != '\0'; j++)
                if ((s[j] < '0' || s[j] > '9'))
                        break ;

	if (s[j] != '\0') {
		if (!(flags & QUIET))
                	error(INFO, "%s: \"%c\" is not a digit 0 - 9\n", 
				orig, s[j]);
                goto dtoll_error;
	} else if (sscanf(s, "%llu", &retval) != 1) {
		if (!(flags & QUIET))
                	error(INFO, "invalid expression\n");
                goto dtoll_error;
        }

        return (retval);

dtoll_error:
        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
                break;
        }

	return ((ulonglong)(-1));
}


/*
 *  Convert a string to a decimal integer value.
 */
unsigned int
dtoi(char *s, int flags, int *errptr)
{
        unsigned int retval;
        char *p;
        int j;

        if (s == NULL) {
		if (!(flags & QUIET))
                	error(INFO, "received NULL string\n");
                goto dtoi_error;
        }

        p = &s[0];
        while (*p++ == ' ')
                s++;

        for (j = 0; s[j] != '\0'; j++)
                if ((s[j] < '0' || s[j] > '9'))
                        break ;

        if (s[j] != '\0' || (sscanf(s, "%d", (int *)&retval) != 1)) {
		if (!(flags & QUIET))
                	error(INFO, "%s: \"%c\" is not a digit 0 - 9\n", 
				s, s[j]);
                goto dtoi_error;
        }

        return(retval);

dtoi_error:
        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
                break;
        }

        return((unsigned int)(-1));
}

/*
 *  Determine whether a string contains only decimal characters.
 *  If count is non-zero, limit the search to count characters.
 */
int
decimal(char *s, int count)
{
    	char *p;
	int cnt, digits;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

    	for (p = &s[0], digits = 0; *p; p++) {
	        switch(*p)
	        {
	            case '0':
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
			digits++;
	            case ' ':
	                break;
	            default:
	                return FALSE;
	        }

		if (count && (--cnt == 0))
			break;
    	}

    	return (digits ? TRUE : FALSE);
}

/*
 *  Extract a hexadecimal number from a string.  If first_instance is FALSE,
 *  and two possibilities are found, a fatal error results.
 */
int
extract_hex(char *s, ulong *result, char stripchar, ulong first_instance)
{
	int i, found;
        char *arglist[MAXARGS];
        int argc;
	ulong value;
	char *buf;

	buf = GETBUF(strlen(s) + 1);
	strcpy(buf, s);
	argc = parse_line(buf, arglist);

	for (i = found = value = 0; i < argc; i++) {
		if (stripchar) 
			strip_ending_char(arglist[i], stripchar);
		
		if (hexadecimal(arglist[i], 0)) {
			if (found) {
				FREEBUF(buf);
				error(FATAL, 
				    "two hexadecimal args in: \"%s\"\n",
					strip_linefeeds(s));
			}
			value = htol(arglist[i], FAULT_ON_ERROR, NULL);
			found = TRUE;
			if (first_instance)
				break;
		}
	}

	FREEBUF(buf);

	if (found) {
		*result = value;
		return TRUE;
	} 

	return FALSE;
}


/*
 *  Determine whether a string contains only ASCII characters.
 */
int
ascii_string(char *s)
{
        char *p;

        for (p = &s[0]; *p; p++) {
		if (!ascii(*p)) 
			return FALSE;
        }

        return TRUE;
}

/*
 *  Check whether a string contains only printable ASCII characters.
 */
int
printable_string(char *s)
{
        char *p;

        for (p = &s[0]; *p; p++) {
		if (!isprint(*p)) 
			return FALSE;
        }

        return TRUE;
}


/*
 *  Determine whether a string contains only hexadecimal characters.
 *  If count is non-zero, limit the search to count characters.
 */
int
hexadecimal(char *s, int count)
{
    	char *p;
	int cnt, digits;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

	for (p = &s[0], digits = 0; *p; p++) {
        	switch(*p) 
		{
	        case 'a':
	        case 'b':
	        case 'c':
	        case 'd':
	        case 'e':
	        case 'f':
	        case 'A':
	        case 'B':
	        case 'C':
	        case 'D':
	        case 'E':
	        case 'F':
	        case '1':
	        case '2':
	        case '3':
	        case '4':
	        case '5':
	        case '6':
	        case '7':
	        case '8':
	        case '9':
	        case '0':
			digits++;
	        case 'x':
	        case 'X':
	                break;

	        case ' ':
	                if (*(p+1) == NULLCHAR)
	                    break;
	                else
	                    return FALSE;
		default:
			return FALSE;
        	}

		if (count && (--cnt == 0))
			break;
    	}

    	return (digits ? TRUE : FALSE);
}

/*
 *  Determine whether a string contains only hexadecimal characters.
 *  and cannot be construed as a decimal number.
 *  If count is non-zero, limit the search to count characters.
 */
int
hexadecimal_only(char *s, int count)
{
    	char *p;
	int cnt, only;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

	only = 0;

	for (p = &s[0]; *p; p++) {
        	switch(*p) 
		{
	        case 'a':
	        case 'b':
	        case 'c':
	        case 'd':
	        case 'e':
	        case 'f':
	        case 'A':
	        case 'B':
	        case 'C':
	        case 'D':
	        case 'E':
	        case 'F':
                case 'x':
                case 'X':
			only++;
			break;
	        case '1':
	        case '2':
	        case '3':
	        case '4':
	        case '5':
	        case '6':
	        case '7':
	        case '8':
	        case '9':
	        case '0':
	                break;

	        case ' ':
	                if (*(p+1) == NULLCHAR)
	                    break;
	                else
	                    return FALSE;
		default:
			return FALSE;
        	}

		if (count && (--cnt == 0))
			break;
    	}

    	return only;
}

/*
 *  Clean a command argument that has an obvious but ignorable error.
 *  The first one is an attached comma to a number, that usually is the 
 *  result of a cut-and-paste of an address from a structure display.  
 *  The second on is an attached colon to a number, usually from a
 *  cut-and-paste of a memory dump.
 *  Add more when they become annoynance.
 *
 *  It presumes args[optind] is the argument being tinkered with, and
 *  always returns TRUE for convenience of use.
 */
int
clean_arg(void)
{
	char buf[BUFSIZE];

	if (LASTCHAR(args[optind]) == ',' || 
	    LASTCHAR(args[optind]) == ':') {
		strcpy(buf, args[optind]);
		LASTCHAR(buf) = NULLCHAR;
		if (IS_A_NUMBER(buf))
			LASTCHAR(args[optind]) = NULLCHAR;
	}

	return TRUE;
}



/*
 *  Translate a hexadecimal string into its ASCII components.
 */
void
cmd_ascii(void)
{
        int i;
        ulonglong value;
	char *s;
        int c, prlen, bytes;

	optind = 1;
	if (!args[optind]) {
		fprintf(fp, "\n");
		fprintf(fp, "      0    1   2   3   4   5   6   7\n");
		fprintf(fp, "    +-------------------------------\n");
		fprintf(fp, "  0 | NUL DLE  SP  0   @   P   '   p\n");
		fprintf(fp, "  1 | SOH DC1  !   1   A   Q   a   q\n");
		fprintf(fp, "  2 | STX DC2  %c   2   B   R   b   r\n", 0x22);
		fprintf(fp, "  3 | ETX DC3  #   3   C   S   c   s\n");
		fprintf(fp, "  4 | EOT DC4  $   4   D   T   d   t\n");
		fprintf(fp, "  5 | ENQ NAK  %c   5   E   U   e   u\n", 0x25);
		fprintf(fp, "  6 | ACK SYN  &   6   F   V   f   v\n");
		fprintf(fp, "  7 | BEL ETB  `   7   G   W   g   w\n");
		fprintf(fp, "  8 |  BS CAN  (   8   H   X   h   x\n");
		fprintf(fp, "  9 |  HT  EM  )   9   I   Y   i   y\n");
		fprintf(fp, "  A |  LF SUB  *   :   J   Z   j   z\n");
		fprintf(fp, "  B |  VT ESC  +   ;   K   [   k   {\n");
		fprintf(fp, "  C |  FF  FS  ,   <   L   %c   l   |\n", 0x5c);
		fprintf(fp, "  D |  CR  GS  _   =   M   ]   m   }\n");
		fprintf(fp, "  E |  SO  RS  .   >   N   ^   n   ~\n");
		fprintf(fp, "  F |  SI  US  /   ?   O   -   o  DEL\n");
		fprintf(fp, "\n");
		return;
	}
	
        while (args[optind]) {

		s = args[optind];
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;

                if (strlen(s) > LONG_PRLEN) {
			prlen = LONG_LONG_PRLEN;
			bytes = sizeof(long long);
		} else {
			prlen = LONG_PRLEN;
			bytes = sizeof(long);
		}
		
                value = htoll(s, FAULT_ON_ERROR, NULL);
                fprintf(fp, "%.*llx: ", prlen, value);
		for (i = 0; i < bytes; i++) {
			c = (value >> (8*i)) & 0xff;
			if ((c >= 0x20) && (c < 0x7f)) {
				fprintf(fp, "%c", (char)c);
				continue;
			}
			if (c > 0x7f) {
				fprintf(fp, "<%02x>", c);
				continue;
			}
			switch (c)
			{
			case 0x0: fprintf(fp, "<NUL>"); break;
			case 0x1: fprintf(fp, "<SOH>"); break;
			case 0x2: fprintf(fp, "<STX>"); break;
			case 0x3: fprintf(fp, "<ETX>"); break;
			case 0x4: fprintf(fp, "<EOT>"); break;
			case 0x5: fprintf(fp, "<ENQ>"); break;
			case 0x6: fprintf(fp, "<ACK>"); break;
			case 0x7: fprintf(fp, "<BEL>"); break;
			case 0x8: fprintf(fp, "<BS>"); break;
			case 0x9: fprintf(fp, "<HT>"); break;
			case 0xa: fprintf(fp, "<LF>"); break;
			case 0xb: fprintf(fp, "<VT>"); break;
			case 0xc: fprintf(fp, "<FF>"); break;
			case 0xd: fprintf(fp, "<CR>"); break;
			case 0xe: fprintf(fp, "<SO>"); break;
			case 0xf: fprintf(fp, "<SI>"); break;
			case 0x10: fprintf(fp, "<DLE>"); break;
			case 0x11: fprintf(fp, "<DC1>"); break;
			case 0x12: fprintf(fp, "<DC2>"); break;
			case 0x13: fprintf(fp, "<DC3>"); break;
			case 0x14: fprintf(fp, "<DC4>"); break;
			case 0x15: fprintf(fp, "<NAK>"); break;
			case 0x16: fprintf(fp, "<SYN>"); break;
			case 0x17: fprintf(fp, "<ETB>"); break;
			case 0x18: fprintf(fp, "<CAN>"); break;
			case 0x19: fprintf(fp, "<EM>"); break;
			case 0x1a: fprintf(fp, "<SUB>"); break;
			case 0x1b: fprintf(fp, "<ESC>"); break;
			case 0x1c: fprintf(fp, "<FS>"); break;
			case 0x1d: fprintf(fp, "<GS>"); break;
			case 0x1e: fprintf(fp, "<RS>"); break;
			case 0x1f: fprintf(fp, "<US>"); break;
			case 0x7f: fprintf(fp, "<DEL>"); break;
			}
		}
		fprintf(fp, "\n");

                optind++;
        }

}

/*
 *  Counts number of leading whitespace characters in a string.
 */
int
count_leading_spaces(char *s)
{
        return (strspn(s, " \t"));
}

/*
 *  Prints the requested number of spaces.
 */
void
pad_line(FILE *filep, int cnt, char c)
{
	int i;

	for (i = 0; i < cnt; i++) 
		fputc(c, filep);
}

/*
 *  Returns appropriate number of inter-field spaces in a usable string.
 *  MINSPACE is defined as -100, but implies the minimum space between two
 *  fields.  Currently this can be either one or two spaces, depending upon
 *  the architecture.  Since the mininum space must be at least 1, MINSPACE,
 *  MINSPACE-1 and MINSPACE+1 are all valid, special numbers.  Otherwise
 *  the space count must be greater than or equal to 0.
 *
 *  If the cnt request is greater than SPACES, a dynamic buffer is
 *  allocated, and normal buffer garbage collection will return it
 *  back to the pool.
 */
char *
space(int cnt)
{
#define SPACES 40
	static char spacebuf[SPACES+1] = { 0 };
	int i;
	char *bigspace;

	if (cnt > SPACES) {
		bigspace = GETBUF(cnt);
		for (i = 0; i < cnt; i++)
			bigspace[i] = ' ';
		bigspace[i] = NULLCHAR;
		return bigspace;
	}

	if (!strlen(spacebuf)) {
		for (i = 0; i < SPACES; i++)
			spacebuf[i] = ' ';
		spacebuf[i] = NULLCHAR; 
	}

	if (cnt < (MINSPACE-1))
		error(FATAL, "illegal spacing request: %d\n", cnt);
	if ((cnt > MINSPACE+1) && (cnt < 0))
		error(FATAL, "illegal spacing request\n");

	switch (cnt)
	{
	case (MINSPACE-1):
		if (VADDR_PRLEN > 8)
			return (&spacebuf[SPACES]);    /* NULL */
		else
			return (&spacebuf[SPACES-1]);  /* 1 space */

	case MINSPACE:
		if (VADDR_PRLEN > 8)
			return (&spacebuf[SPACES-1]);  /* 1 space */
		else
			return (&spacebuf[SPACES-2]);  /* 2 spaces */

	case (MINSPACE+1):
                if (VADDR_PRLEN > 8) 
                        return (&spacebuf[SPACES-2]);  /* 2 spaces */
                else    
                        return (&spacebuf[SPACES-3]);  /* 3 spaces */

	default:
		return (&spacebuf[SPACES-cnt]);        /* as requested */
	}
}

/*
 *  Determine whether substring s1, with length len, and contained within
 *  string s, is surrounded by <bracket> characters.  If len is 0, calculate
 *  it.
 */
int
bracketed(char *s, char *s1, int len)
{
	char *s2;

	if (!len) {
		if (!(s2 = strstr(s1, ">")))
			return FALSE;
		len = s2-s1;
	}

	if (((s1-s) < 1) || (*(s1-1) != '<') || 
	    ((s1+len) >= &s[strlen(s)]) || (*(s1+len) != '>'))
		return FALSE;

	return TRUE;
}

/*
 *  Counts the number of a specified character in a string.
 */
int
count_chars(char *s, char c)
{
	char *p;
	int count;

	if (!s)
		return 0;

	count = 0;

	for (p = s; *p; p++) {
		if (*p == c)
			count++;
	}

	return count;
}

/*
 *  Counts the number of a specified characters in a buffer.
 */
long count_buffer_chars(char *bufptr, char c, long len)
{
	long i, cnt;

	for (i = cnt = 0; i < len; i++, bufptr++) {
		if (*bufptr == c)
			cnt++;
	}

	return cnt;
}

/*
 *  Concatenates the tokens in the global args[] array into one string,
 *  separating each token with one space.  If the no_options flag is set,
 *  don't include any args beginning with a dash character.
 */
char *
concat_args(char *buf, int arg, int no_options)
{
	int i;

	BZERO(buf, BUFSIZE);

        for (i = arg; i < argcnt; i++) {
		if (no_options && STRNEQ(args[i], "-"))
			continue;
                strcat(buf, args[i]);
                strcat(buf, " ");
        }

	return(strip_ending_whitespace(buf));
}

/*
 *  Shifts the contents of a string to the left by cnt characters, 
 *  disposing the leftmost characters.
 */
char *
shift_string_left(char *s, int cnt)
{
	int origlen;

	if (!cnt)
		return(s);

	origlen = strlen(s);
	memmove(s, s+cnt, (origlen-cnt));
	*(s+(origlen-cnt)) = NULLCHAR;
	return(s);
}

/*
 *  Shifts the contents of a string to the right by cnt characters,
 *  inserting space characters.  (caller confirms space is available)
 */
char *
shift_string_right(char *s, int cnt)
{
        int origlen;

	if (!cnt)
		return(s);

        origlen = strlen(s);
        memmove(s+cnt, s, origlen);
        s[origlen+cnt] = NULLCHAR;
	return(memset(s, ' ', cnt));
}

/*
 *  Create a string in a buffer of a given size, centering, or justifying 
 *  left or right as requested.  If the opt argument is used, then the string
 *  is created with its string/integer value.  If opt is NULL, then the
 *  string is already in contained in string s (not justified).  Note that
 *  flag LONGLONG_HEX implies that opt is a ulonglong pointer to the 
 *  actual value.
 */
char *
mkstring(char *s, int size, ulong flags, const char *opt)
{
	int len;
	int extra;
	int left;
	int right;

	switch (flags & (LONG_DEC|SLONG_DEC|LONG_HEX|INT_HEX|INT_DEC|LONGLONG_HEX|ZERO_FILL))
	{
	case LONG_DEC:
		sprintf(s, "%lu", (ulong)opt);
		break;
	case SLONG_DEC:
		sprintf(s, "%ld", (ulong)opt);
		break;
	case LONG_HEX:
		sprintf(s, "%lx", (ulong)opt);
		break;
	case (LONG_HEX|ZERO_FILL):
		if (VADDR_PRLEN == 8)
			sprintf(s, "%08lx", (ulong)opt);
		else if (VADDR_PRLEN == 16)
			sprintf(s, "%016lx", (ulong)opt);
		break;
	case INT_DEC:
		sprintf(s, "%u", (uint)((ulong)opt));
		break;
	case INT_HEX:
		sprintf(s, "%x", (uint)((ulong)opt));
		break;
	case LONGLONG_HEX:
		sprintf(s, "%llx", *((ulonglong *)opt));
		break;
	default:
		if (opt)
			strcpy(s, opt);
		break;
	}

	/*
	 *  At this point, string s has the string to be justified,
	 *  and has room to work with.  The relevant flags from this
	 *  point on are of CENTER, LJUST and RJUST.  If the length 
	 *  of string s is already larger than the requested size, 
	 *  just return it as is.
	 */
	len = strlen(s);
	if (size <= len) 
		return(s);
	extra = size - len;

	if (flags & CENTER) {
		/*
		 *  If absolute centering is not possible, justify the
		 *  string as requested -- or to the left if no justify
		 *  argument was passed in.
		 */
		if (extra % 2) {
			switch (flags & (LJUST|RJUST))
			{
			default:
			case LJUST:
				right = (extra/2) + 1;
				left = extra/2;
				break;
			case RJUST:
				right = extra/2;
				left = (extra/2) + 1;
				break;
			}
		}
		else 
			left = right = extra/2;

		shift_string_right(s, left);
		len = strlen(s);
		memset(s + len, ' ', right);
		s[len + right] = NULLCHAR;
	
		return(s);
	}

	if (flags & LJUST) {
		len = strlen(s);
		memset(s + len, ' ', extra);
		s[len + extra] = NULLCHAR;
	} else if (flags & RJUST) 
		shift_string_right(s, extra);

	return(s);
}

/*
 *  Prints the requested number of BACKSPACE characters.
 */
void
backspace(int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) 
		fprintf(fp, "\b");
}

/*
 *  Set/display process context or internal variables.  Processes are set
 *  by their task or PID number, or to the panic context with the -p flag.
 *  Internal variables may be viewed or changed, depending whether an argument 
 *  follows the variable name.  If no arguments are entered, the current
 *  process context is dumped.  The current set of variables and their
 *  acceptable settings are:
 *
 *        debug  "on", "off", or any number.  "on" sets it to a value of 1.
 *         hash  "on", "off", or any number.  Non-zero numbers are converted 
 *               to "on", zero is converted to "off".
 *       scroll  "on", "off", or any number.  Non-zero numbers are converted 
 *               to "on", zero is converted to "off".
 *       silent  "on", "off", or any number.  Non-zero numbers are converted
 *               to "on", zero is converted to "off".
 *      refresh  "on", "off", or any number.  Non-zero numbers are converted
 *               to "on", zero is converted to "off".
 *          sym  regular filename
 *      console  device filename
 *        radix  10 or 16
 *         core  (no arg) drop core when error() is called.
 *           vi  (no arg) set editing mode to vi (from .rc file only).
 *        emacs  (no arg) set editing mode to emacs (from .rc file only).
 *     namelist  kernel name (from .rc file only).
 *     dumpfile  dumpfile name (from .rc file only).
 *
 *  gdb variable settings not changeable by gdb's "set" command:
 *
 *    print_max  value (default is 200).
 */
void
cmd_set(void)
{
	int i, c;
	ulong value;
	int cpu, runtime, from_rc_file;
	char buf[BUFSIZE];
	char *extra_message;
	struct task_context *tc;
	struct syment *sp;

#define defer()  do { } while (0)
#define already_done()  do { } while (0)
#define ignore()  do { } while (0)

	extra_message = NULL;
	runtime = pc->flags & RUNTIME ? TRUE : FALSE;
	from_rc_file = pc->curcmd_flags & FROM_RCFILE ? TRUE : FALSE;

        while ((c = getopt(argcnt, args, "pvc:a:")) != EOF) {
                switch(c)
		{
		case 'c':
			if (XEN_HYPER_MODE() || (pc->flags & MINIMAL_MODE))
				option_not_supported(c);

			if (!runtime)
				return;

		        if (ACTIVE()) {
                		error(INFO, "not allowed on a live system\n");
				argerrs++;
				break;
			}
			cpu = dtoi(optarg, FAULT_ON_ERROR, NULL);
			set_cpu(cpu);
			return;

		case 'p':
			if (XEN_HYPER_MODE() || (pc->flags & MINIMAL_MODE))
				option_not_supported(c);

			if (!runtime)
				return;

			if (ACTIVE()) {
				set_context(tt->this_task, NO_PID);
				show_context(CURRENT_CONTEXT());
				return;
			}

			if (!tt->panic_task) {
                		error(INFO, "no panic task found!\n");
				return;
			}
        		set_context(tt->panic_task, NO_PID);
			show_context(CURRENT_CONTEXT());
			return;

		case 'v':
			if (!runtime)
				return;

			show_options();
			return;

		case 'a':
			if (XEN_HYPER_MODE() || (pc->flags & MINIMAL_MODE))
				option_not_supported(c);

			if (!runtime)
				return;

			if (ACTIVE())
				error(FATAL, 
				    "-a option not allowed on live systems\n");

	                switch (str_to_context(optarg, &value, &tc))
	                {
	                case STR_PID:
				if ((i = TASKS_PER_PID(value)) > 1)
					error(FATAL, 
					    "pid %d has %d tasks: "
					    "use a task address\n",
						value, i);
	                        break;
	
	                case STR_TASK:
	                        break;
	
	                case STR_INVALID:
	                        error(FATAL, "invalid task or pid value: %s\n",
	                                optarg);
	                }
		
			cpu = tc->processor;
			tt->active_set[cpu] = tc->task;
			if (tt->panic_threads[cpu])
				tt->panic_threads[cpu] = tc->task;
			fprintf(fp, 
			    "\"%s\" task %lx has been marked as the active task on cpu %d\n",
				tc->comm, tc->task, cpu);
			return;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs) {
		if (runtime)
			cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	if (!args[optind]) {
		if (XEN_HYPER_MODE())
			error(INFO, 
			    "requires an option with the Xen hypervisor\n");
		else if (pc->flags & MINIMAL_MODE)
			show_options();
		else if (runtime)
			show_context(CURRENT_CONTEXT());
		return;
	}

	while (args[optind]) {
		if (STREQ(args[optind], "debug")) {
                        if (args[optind+1]) {
                                optind++;
				if (!runtime)
					defer();
                                else if (STREQ(args[optind], "on"))
                                        pc->debug = 1;
                                else if (STREQ(args[optind], "off"))
                                        pc->debug = 0;
				else if (IS_A_NUMBER(args[optind])) 
					pc->debug = stol(args[optind], 
						FAULT_ON_ERROR, NULL);
				else
					goto invalid_set_command;
                        }
			if (runtime)
                        	fprintf(fp, "debug: %ld\n", pc->debug);

			set_lkcd_debug(pc->debug);
			set_vas_debug(pc->debug);
			return;

                } else if (STREQ(args[optind], "hash")) {
                        if (args[optind+1]) {
                                optind++;
				if (!runtime)
					defer();
                                else if (STREQ(args[optind], "on"))
                                        pc->flags |= HASH;
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~HASH;
				else if (IS_A_NUMBER(args[optind])) {
					value = stol(args[optind],
                                    		FAULT_ON_ERROR, NULL);
					if (value)
						pc->flags |= HASH;
					else
						pc->flags &= ~HASH;
				} else
					goto invalid_set_command;
                        }

			if (runtime)
                        	fprintf(fp, "hash: %s\n",
                                	pc->flags & HASH ? "on" : "off");
			return;

                } else if (STREQ(args[optind], "unwind")) {
                        if (args[optind+1]) {
                                optind++;
				if (!runtime)
					defer();
                                else if (STREQ(args[optind], "on")) {
				    	if ((kt->flags & DWARF_UNWIND_CAPABLE) ||
					    !runtime) {
                                        	kt->flags |= DWARF_UNWIND;
						kt->flags &= ~NO_DWARF_UNWIND;
					}
                                } else if (STREQ(args[optind], "off")) {
                                        kt->flags &= ~DWARF_UNWIND;
					if (!runtime)
						kt->flags |= NO_DWARF_UNWIND;
				} else if (IS_A_NUMBER(args[optind])) {
					value = stol(args[optind],
                                    		FAULT_ON_ERROR, NULL);
					if (value) {
				    		if ((kt->flags & DWARF_UNWIND_CAPABLE) ||
						    !runtime) {
							kt->flags |= DWARF_UNWIND;
							kt->flags &= ~NO_DWARF_UNWIND;
						}
					} else {
						kt->flags &= ~DWARF_UNWIND;
						if (!runtime)
							kt->flags |= NO_DWARF_UNWIND;
					}
				} else
					goto invalid_set_command;
                        }

			if (runtime)
                        	fprintf(fp, "unwind: %s\n",
                                	kt->flags & DWARF_UNWIND ? "on" : "off");
			return;

               } else if (STREQ(args[optind], "refresh")) {
                        if (args[optind+1]) {
                                optind++;
				if (!runtime)
					defer();
                                else if (STREQ(args[optind], "on"))
                                        tt->flags |= TASK_REFRESH;
                                else if (STREQ(args[optind], "off")) {
                                        tt->flags &= ~TASK_REFRESH;
					if (!runtime)
						tt->flags |= TASK_REFRESH_OFF;
                                } else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value)
                                                tt->flags |= TASK_REFRESH;
                                        else {
                                                tt->flags &= ~TASK_REFRESH;
						if (!runtime)
							tt->flags |= 
							    TASK_REFRESH_OFF;
					}
                                } else
					goto invalid_set_command;
                        }

                        if (runtime)
                                fprintf(fp, "refresh: %s\n",
                               	    tt->flags & TASK_REFRESH ?  "on" : "off");
			return;

               } else if (STREQ(args[optind], "gdb")) {
                        if (args[optind+1]) {
                                optind++;
				if (!runtime)
					defer();
                                else if (STREQ(args[optind], "on")) {
					if (pc->flags & MINIMAL_MODE)
						goto invalid_set_command;
					else
                                        	pc->flags2 |= GDB_CMD_MODE;
                                } else if (STREQ(args[optind], "off"))
                                        pc->flags2 &= ~GDB_CMD_MODE;
                                else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value) {
						if (pc->flags & MINIMAL_MODE)
							goto invalid_set_command;
						else
                                                	pc->flags2 |= GDB_CMD_MODE;
                                        } else
                                                pc->flags2 &= ~GDB_CMD_MODE;
                                } else
					goto invalid_set_command;

				set_command_prompt(pc->flags2 & GDB_CMD_MODE ?
					"gdb> " : NULL);
                        }

                        if (runtime)
                                fprintf(fp, "gdb: %s\n",
                               	    pc->flags2 & GDB_CMD_MODE ?  "on" : "off");
			return;

               } else if (STREQ(args[optind], "scroll")) {
                        if (args[optind+1] && pc->scroll_command) {
                                optind++;
				if (from_rc_file)
					already_done();
                                else if (STREQ(args[optind], "on"))
                                        pc->flags |= SCROLL;
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~SCROLL;
				else if (STREQ(args[optind], "more"))
					pc->scroll_command = SCROLL_MORE;
				else if (STREQ(args[optind], "less"))
					pc->scroll_command = SCROLL_LESS;
				else if (STREQ(args[optind], "CRASHPAGER")) {
					if (CRASHPAGER_valid())
						pc->scroll_command = SCROLL_CRASHPAGER;
				} else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value)
                                                pc->flags |= SCROLL;
                                        else
                                                pc->flags &= ~SCROLL;
                                } else
					goto invalid_set_command;
                        }

			if (runtime) {
				fprintf(fp, "scroll: %s ",
					pc->flags & SCROLL ? "on" : "off");
				switch (pc->scroll_command)
				{
				case SCROLL_LESS:
					fprintf(fp, "(/usr/bin/less)\n");
					break;
				case SCROLL_MORE:
					fprintf(fp, "(/bin/more)\n");
					break;
				case SCROLL_NONE:
					fprintf(fp, "(none)\n");
					break;
				case SCROLL_CRASHPAGER:
					fprintf(fp, "(CRASHPAGER: %s)\n", getenv("CRASHPAGER"));
					break;
				}
			}

			return;

               } else if (STREQ(args[optind], "silent")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on")) {
                                        pc->flags |= SILENT;
					pc->flags &= ~SCROLL;
				}
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~SILENT;
                                else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value) {
                                                pc->flags |= SILENT;
						pc->flags &= ~SCROLL;
					}
                                        else
                                                pc->flags &= ~SILENT;
                                } else
					goto invalid_set_command;

				if (!(pc->flags & SILENT))
                                	fprintf(fp, "silent: off\n");

                        } else if (runtime && !(pc->flags & SILENT))
                               	fprintf(fp, "silent: off\n");
			return;

                } else if (STREQ(args[optind], "console")) {
			int assignment;

                        if (args[optind+1]) {
                                create_console_device(args[optind+1]);
				optind++;
				assignment = optind;
			} else
				assignment = 0;

			if (runtime) {
				fprintf(fp, "console: ");
				if (pc->console)
					fprintf(fp, "%s\n", pc->console);
				else {
					if (assignment)
						fprintf(fp, 
					            "assignment to %s failed\n",
						    	args[assignment]);
					else
						fprintf(fp, "not set\n");
				}		
			}
			return;

		} else if (STREQ(args[optind], "core")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on"))
                                        pc->flags |= DROP_CORE;
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~DROP_CORE;
                                else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value)
                                                pc->flags |= DROP_CORE;
                                        else
                                                pc->flags &= ~DROP_CORE;
                                } else
                                        goto invalid_set_command;
                        }
		
			if (runtime) {
				fprintf(fp, "core: %s on error message)\n",
					pc->flags & DROP_CORE ? 
					"on (drop core" : 
					"off (do NOT drop core");
			}
			return;

                } else if (STREQ(args[optind], "radix")) {
                       if (args[optind+1]) {
                                optind++;
				if (!runtime)
					defer();
				else if (from_rc_file && 
				    (pc->flags2 & RADIX_OVERRIDE))
					ignore();
                                else if (STREQ(args[optind], "10") ||
				    STRNEQ(args[optind], "dec") ||
				    STRNEQ(args[optind], "ten")) 
					pc->output_radix = 10;
                                else if (STREQ(args[optind], "16") ||
			            STRNEQ(args[optind], "hex") ||
				    STRNEQ(args[optind], "six")) 
					pc->output_radix = 16;
				else 
					goto invalid_set_command;
			} 

                        if (runtime) {
				sprintf(buf, "set output-radix %d",
					pc->output_radix);
                                gdb_pass_through(buf, NULL, GNU_FROM_TTY_OFF);
                        	fprintf(fp, "output radix: %d (%s)\n",
					pc->output_radix, 
					pc->output_radix == 10 ? 
					"decimal" : "hex");
			}
			return;

                } else if (STREQ(args[optind], "hex")) {
			if (from_rc_file && (pc->flags2 & RADIX_OVERRIDE))
				ignore();
			else if (runtime) {
				pc->output_radix = 16;
				gdb_pass_through("set output-radix 16", 
					NULL, GNU_FROM_TTY_OFF);
				fprintf(fp, "output radix: 16 (hex)\n");
			}
			return;

                } else if (STREQ(args[optind], "dec")) {
			if (from_rc_file && (pc->flags2 & RADIX_OVERRIDE))
				ignore();
			else if (runtime) {
				pc->output_radix = 10;
                                gdb_pass_through("set output-radix 10", 
                                        NULL, GNU_FROM_TTY_OFF);
				fprintf(fp, "output radix: 10 (decimal)\n");
			}
			return;

               } else if (STREQ(args[optind], "edit")) {
                        if (args[optind+1]) {
				if (runtime && !from_rc_file)
					error(FATAL, 
		                "cannot change editing mode during runtime\n");
                                optind++;
				if (from_rc_file)
					already_done();
                                else if (STREQ(args[optind], "vi"))
                                        pc->editing_mode = "vi";
                                else if (STREQ(args[optind], "emacs"))
                                        pc->editing_mode = "emacs";
				else
                                        goto invalid_set_command;
                        }

                        if (runtime)
                                fprintf(fp, "edit: %s\n", pc->editing_mode);
                        return;

                } else if (STREQ(args[optind], "vi")) {
			if (runtime) {
				if (!from_rc_file)
					error(FATAL, 
		               "cannot change editing mode during runtime\n"); 
				fprintf(fp, "edit: %s\n", pc->editing_mode);
			} else
				pc->editing_mode = "vi";
			return;

                } else if (STREQ(args[optind], "emacs")) {
			if (runtime) {
				if (!from_rc_file)
					error(FATAL, 
		               "cannot change %s editing mode during runtime\n",
						pc->editing_mode);
				fprintf(fp, "edit: %s\n", pc->editing_mode);
			} else
				pc->editing_mode = "emacs";
			return;

                } else if (STREQ(args[optind], "print_max")) {
			optind++;
			if (args[optind]) {
				if (!runtime)
					defer();
				else if (decimal(args[optind], 0))
					*gdb_print_max = atoi(args[optind]);
				else if (hexadecimal(args[optind], 0))
					*gdb_print_max = (unsigned int)
					    htol(args[optind], 
						FAULT_ON_ERROR, NULL);
				else
					goto invalid_set_command;

			}
			if (runtime)
				fprintf(fp, "print_max: %d\n", *gdb_print_max);
			return;

                } else if (STREQ(args[optind], "scope")) {
			optind++;
			if (args[optind]) {
				if (!runtime)
					defer();
				else if (can_eval(args[optind])) 
					value = eval(args[optind], FAULT_ON_ERROR, NULL);
				else if (hexadecimal(args[optind], 0))
					value = htol(args[optind], FAULT_ON_ERROR, NULL);
				else if ((sp = symbol_search(args[optind])))
					value = sp->value;
				else
					goto invalid_set_command;

				if (runtime) {
					if (gdb_set_crash_scope(value, args[optind]))
						pc->scope = value;
					else
						return;
				}
			}
			if (runtime) {
				fprintf(fp, "scope: %lx ", pc->scope);
				if (pc->scope)
					fprintf(fp, "(%s)\n", 
						value_to_symstr(pc->scope, buf, 0));
				else
					fprintf(fp, "(not set)\n");
			}
			return;

                } else if (STREQ(args[optind], "null-stop")) {
			optind++;
			if (args[optind]) {
				if (!runtime)
					defer();
				else if (STREQ(args[optind], "on"))
					*gdb_stop_print_at_null = 1;
				else if (STREQ(args[optind], "off"))
					*gdb_stop_print_at_null = 0;
				else if (IS_A_NUMBER(args[optind])) {
					value = stol(args[optind],
						FAULT_ON_ERROR, NULL);
					if (value)
						*gdb_stop_print_at_null = 1;
					else
						*gdb_stop_print_at_null = 0;
					} else
						goto invalid_set_command;
			}
			if (runtime)
				fprintf(fp, "null-stop: %s\n", 
					*gdb_stop_print_at_null ? "on" : "off");
			return;

                } else if (STREQ(args[optind], "print_array")) {
			optind++;
			if (args[optind]) {
				if (!runtime)
					defer();
				else if (STREQ(args[optind], "on"))
					*gdb_prettyprint_arrays = 1;
				else if (STREQ(args[optind], "off"))
					*gdb_prettyprint_arrays = 0;
				else if (IS_A_NUMBER(args[optind])) {
					value = stol(args[optind],
						FAULT_ON_ERROR, NULL);
					if (value)
						*gdb_prettyprint_arrays = 1;
					else
						*gdb_prettyprint_arrays = 0;
					} else
						goto invalid_set_command;
			}
			if (runtime)
				fprintf(fp, "print_array: %s\n", 
					*gdb_prettyprint_arrays ? "on" : "off");
			return;

                } else if (STREQ(args[optind], "namelist")) {
			optind++;
                        if (!runtime && args[optind]) {
                		if (!is_elf_file(args[optind])) 
                                	error(FATAL, 
			       "%s: not a kernel namelist (from .%src file)\n",
                                        	args[optind],
						pc->program_name);
                                if ((pc->namelist = (char *)
                                    malloc(strlen(args[optind])+1)) == NULL) {
                                        error(INFO,
                                  "cannot malloc memory for namelist: %s: %s\n",
                                                args[optind], strerror(errno));
                                } else
                                        strcpy(pc->namelist, args[optind]);
			}
			if (runtime)
				fprintf(fp, "namelist: %s\n", pc->namelist);
			return;

                } else if (STREQ(args[optind], "free")) {
			if (!runtime)
				defer();
			else
				fprintf(fp, "%d pages freed\n",
					dumpfile_memory(DUMPFILE_FREE_MEM));
			return;

                } else if (STREQ(args[optind], "data_debug")) {

			pc->flags |= DATADEBUG;
			return;

                } else if (STREQ(args[optind], "zero_excluded")) {

                        if (args[optind+1]) {
                                optind++;
				if (from_rc_file)
					already_done();
                                else if (STREQ(args[optind], "on")) {
                                        *diskdump_flags |= ZERO_EXCLUDED;
					sadump_set_zero_excluded();
                                } else if (STREQ(args[optind], "off")) {
                                        *diskdump_flags &= ~ZERO_EXCLUDED;
					sadump_unset_zero_excluded();
				} else if (IS_A_NUMBER(args[optind])) {
					value = stol(args[optind],
                                    		FAULT_ON_ERROR, NULL);
					if (value) {
                                        	*diskdump_flags |= ZERO_EXCLUDED;
						sadump_set_zero_excluded();
					} else {
                                        	*diskdump_flags &= ~ZERO_EXCLUDED;
						sadump_unset_zero_excluded();
					}
				} else
					goto invalid_set_command;
                        }

			if (runtime)
                        	fprintf(fp, "zero_excluded: %s\n",
					(*diskdump_flags & ZERO_EXCLUDED) ||
					sadump_is_zero_excluded() ?
					"on" : "off");
			return;

                } else if (STREQ(args[optind], "offline")) {

                        if (args[optind+1]) {
                                optind++;
				if (from_rc_file)
					already_done();
                                else if (STREQ(args[optind], "show"))
                                        pc->flags2 &= ~OFFLINE_HIDE;
                                else if(STREQ(args[optind], "hide"))
                                        pc->flags2 |= OFFLINE_HIDE;
                                else
                                        goto invalid_set_command;
                        }

			if (runtime)
				fprintf(fp, "      offline: %s\n",
					pc->flags2 & OFFLINE_HIDE ? "hide" : "show");

			return;

		} else if (STREQ(args[optind], "redzone")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on"))
                                        pc->flags2 |= REDZONE;
                                else if (STREQ(args[optind], "off"))
                                        pc->flags2 &= ~REDZONE;
                                else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value)
                                                pc->flags2 |= REDZONE;
                                        else
                                                pc->flags2 &= ~REDZONE;
                                } else
                                        goto invalid_set_command;
                        }
		
			if (runtime) {
				fprintf(fp, "redzone: %s\n",
					pc->flags2 & REDZONE ? 
					"on" : "off");
			}
			return;

                } else if (STREQ(args[optind], "error")) {
                        if (args[optind+1]) {
                                optind++;
                                if (!set_error(args[optind]))
                                        return;
                        }

                        if (runtime) {
                                fprintf(fp, "error: %s\n",
                                        pc->error_path);
                        }
                        return;

		} else if (XEN_HYPER_MODE()) {
			error(FATAL, "invalid argument for the Xen hypervisor\n");
		} else if (pc->flags & MINIMAL_MODE) {
			error(FATAL, "invalid argument in minimal mode\n");
		} else if (runtime) {
			ulong pid, task;

	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                pid = value;
                                task = NO_TASK;
                        	if (set_context(task, pid))
                                	show_context(CURRENT_CONTEXT());
	                        break;
	
	                case STR_TASK:
                                task = value;
                                pid = NO_PID;
                                if (set_context(task, pid))
                                        show_context(CURRENT_CONTEXT()); 
	                        break;
	
	                case STR_INVALID:
	                        error(INFO, "invalid task or pid value: %s\n",
	                                args[optind]);
	                        break;
	                }
		} else
			console("set: ignoring \"%s\"\n", args[optind]);

		optind++;
	}

	return;

invalid_set_command:

	sprintf(buf, "invalid command");
	if (!runtime)
		sprintf(&buf[strlen(buf)], " in .%src file", pc->program_name);
	strcat(buf, ": ");
	for (i = 0; i < argcnt; i++)
		sprintf(&buf[strlen(buf)], "%s ", args[i]);
	strcat(buf, "\n");
	if (extra_message)
		strcat(buf, extra_message);
	error(runtime ? FATAL : INFO, buf);

#undef defer
#undef already_done
#undef ignore
}

/*
 *  Display the set of settable internal variables.
 */
static void
show_options(void)
{
	char buf[BUFSIZE];

	fprintf(fp, "        scroll: %s ",
		pc->flags & SCROLL ? "on" : "off");
	switch (pc->scroll_command)
	{
	case SCROLL_LESS:
		fprintf(fp, "(/usr/bin/less)\n");
		break;
	case SCROLL_MORE:
		fprintf(fp, "(/bin/more)\n");
		break;
	case SCROLL_NONE:
		fprintf(fp, "(none)\n");
		break;
	case SCROLL_CRASHPAGER:
		fprintf(fp, "(CRASHPAGER: %s)\n", getenv("CRASHPAGER"));
		break;
	}
        fprintf(fp, "         radix: %d (%s)\n", pc->output_radix,
                pc->output_radix == 10 ? "decimal" :
                pc->output_radix == 16 ? "hexadecimal" : "unknown");
	fprintf(fp, "       refresh: %s\n", tt->flags & TASK_REFRESH ? "on" : "off");
	fprintf(fp, "     print_max: %d\n", *gdb_print_max);
	fprintf(fp, "   print_array: %s\n", *gdb_prettyprint_arrays ? "on" : "off");
	fprintf(fp, "       console: %s\n", pc->console ? 
		pc->console : "(not assigned)");
	fprintf(fp, "         debug: %ld\n", pc->debug);
	fprintf(fp, "          core: %s\n", pc->flags & DROP_CORE ? "on" : "off");
	fprintf(fp, "          hash: %s\n", pc->flags & HASH ? "on" : "off");
	fprintf(fp, "        silent: %s\n", pc->flags & SILENT ? "on" : "off"); 
	fprintf(fp, "          edit: %s\n", pc->editing_mode);
	fprintf(fp, "      namelist: %s\n", pc->namelist);
	fprintf(fp, "      dumpfile: %s\n", pc->dumpfile);
	fprintf(fp, "        unwind: %s\n", kt->flags & DWARF_UNWIND ? "on" : "off");
	fprintf(fp, " zero_excluded: %s\n",
		(*diskdump_flags & ZERO_EXCLUDED) || sadump_is_zero_excluded() ?
		"on" : "off");
	fprintf(fp, "     null-stop: %s\n", *gdb_stop_print_at_null ? "on" : "off");
	fprintf(fp, "           gdb: %s\n", pc->flags2 & GDB_CMD_MODE ? "on" : "off");
	fprintf(fp, "         scope: %lx ", pc->scope);
	if (pc->scope)
		fprintf(fp, "(%s)\n", value_to_symstr(pc->scope, buf, 0));
	else
		fprintf(fp, "(not set)\n");
	fprintf(fp, "       offline: %s\n", pc->flags2 & OFFLINE_HIDE ? "hide" : "show");
	fprintf(fp, "       redzone: %s\n", pc->flags2 & REDZONE ? "on" : "off");
	fprintf(fp, "         error: %s\n", pc->error_path);
}




/*
 *  Evaluate an expression, which can consist of a single symbol, single value,
 *  or an expression consisting of two values and an operator.  If the 
 *  expression contains redirection characters, the whole expression must
 *  be enclosed with parentheses.  The result is printed in decimal, hex,
 *  octal and binary.  Input number values can only be hex or decimal, with
 *  a bias towards decimal (use 0x when necessary).
 */
void 
cmd_eval(void)
{
	int flags;
	int bitflag, longlongflag, longlongflagforce;
	struct number_option nopt;
	char buf1[BUFSIZE];

	/*
	 *  getopt() is not used to avoid confusion with minus sign.
	 */
	optind = 1;
	bitflag = 0;
	longlongflag = longlongflagforce = 0;
	BZERO(&nopt, sizeof(struct number_option));

	if (STREQ(args[optind], "-lb") || STREQ(args[optind], "-bl")) {
		longlongflagforce++;
		bitflag++;
		optind++;
	} else if (STREQ(args[optind], "-l")) {
		longlongflagforce++;
		optind++;
		if (STREQ(args[optind], "-b") && args[optind+1]) { 
			optind++;
			bitflag++;
		}
	} else if (STREQ(args[optind], "-b")) { 
		if (STREQ(args[optind+1], "-l")) { 
			if (args[optind+2]) {
				bitflag++;
				longlongflagforce++;
				optind += 2;
			} else
                		cmd_usage(pc->curcmd, SYNOPSIS);
		} else if (args[optind+1]) {
			bitflag++;
			optind++;
		}
	}

        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

	longlongflag = BITS32() ? TRUE : FALSE;
	flags = longlongflag ? (LONG_LONG|RETURN_ON_ERROR) : FAULT_ON_ERROR;

	if(!BITS32())
		longlongflagforce = 0;

	BZERO(buf1, BUFSIZE);
	buf1[0] = '(';

        while (args[optind]) {
                if (*args[optind] == '(') {
			if (eval_common(args[optind], flags, NULL, &nopt))
				print_number(&nopt, bitflag, longlongflagforce);
			else
				error(FATAL, "invalid expression: %s\n", 
					args[optind]);
			return;
                }
		else {
			strcat(buf1, args[optind]);
			strcat(buf1, " ");
		}
		optind++;
        }
	clean_line(buf1);
	strcat(buf1, ")");

	if (eval_common(buf1, flags, NULL, &nopt))
        	print_number(&nopt, bitflag, longlongflagforce);
	else
		error(FATAL, "invalid expression: %s\n", buf1);
}

/*
 *  Pre-check a string for eval-worthiness.  This allows callers to avoid
 *  having to encompass a non-whitespace expression with parentheses.
 *  Note that the data being evaluated is not error-checked here, but
 *  rather that it exists in the proper format.
 */
int
can_eval(char *s)
{
	char *op;
	char *element1, *element2;
	char work[BUFSIZE];

	/*
	 *  If we've got a () pair containing any sort of stuff in between,
	 *  then presume it's eval-able.  It might contain crap, but it 
	 *  should be sent to eval() regardless.
	 */
	if ((FIRSTCHAR(s) == '(') &&
	    (count_chars(s, '(') == 1) &&
	    (count_chars(s, ')') == 1) &&
	    (strlen(s) > 2) &&
	    (LASTCHAR(s) == ')'))
		return TRUE;

	/*
	 *  If the string contains any of the operators except the shifters,
         *  and has any kind of data on either side, it's also eval-able.
	 */
	strcpy(work, s);

        if (!(op = strpbrk(work, "><+-&|*/%^")))
		return FALSE; 

        element1 = &work[0];
        *op = NULLCHAR;
	element2 = op+1;

	if (!strlen(element1) || !strlen(element2))
		return FALSE;

	return TRUE;
}

/*
 *  Evaluate an expression involving two values and an operator.  
 */
#define OP_ADD   (1)
#define OP_SUB   (2)
#define OP_AND   (3)
#define OP_OR    (4)
#define OP_MUL   (5)
#define OP_DIV   (6)
#define OP_MOD   (7)
#define OP_SL    (8)
#define OP_SR    (9)
#define OP_EXOR  (10)
#define OP_POWER (11)

ulong
eval(char *s, int flags, int *errptr)
{
	struct number_option nopt;

	if (eval_common(s, flags, errptr, &nopt)) {
		return(nopt.num);
	} else {
	        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	        {
	        case FAULT_ON_ERROR:
	                error(FATAL, "invalid expression: %s\n", s);
	
	        case RETURN_ON_ERROR:
	                error(INFO, "invalid expression: %s\n", s);
	                if (errptr)
	                        *errptr = TRUE;
	                break;
	        }
        	return UNUSED;
	}
}

ulonglong
evall(char *s, int flags, int *errptr)
{
        struct number_option nopt;

	if (BITS32())
		flags |= LONG_LONG;

        if (eval_common(s, flags, errptr, &nopt)) {
                return(nopt.ll_num);
        } else {
                switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
                {
                case FAULT_ON_ERROR:
                        error(FATAL, "invalid expression: %s\n", s);

                case RETURN_ON_ERROR:
                        error(INFO, "invalid expression: %s\n", s);
                        if (errptr)
                                *errptr = TRUE;
                        break;
                }
                return UNUSED;
        }
}


int
eval_common(char *s, int flags, int *errptr, struct number_option *np)
{
	char *p1, *p2;
        char *op, opcode;
	ulong value1;
	ulong value2;
	ulonglong ll_value1;
	ulonglong ll_value2;
	char work[BUFSIZE];
	char *element1;
	char *element2;
	struct syment *sp;

	opcode = 0;
	value1 = value2 = 0;
	ll_value1 = ll_value2 = 0;

	if (strstr(s, "(") || strstr(s, ")")) {
		p1 = s;
		if (*p1 != '(')
			goto malformed;
		if (LASTCHAR(s) != ')')
			goto malformed;
		p2 = &LASTCHAR(s);
		if (strstr(s, ")") != p2)
			goto malformed;
	
		strcpy(work, p1+1);
		LASTCHAR(work) = NULLCHAR;
	
		if (strstr(work, "(") || strstr(work, ")")) 
			goto malformed;
	} else
		strcpy(work, s);

        if (work[0] == '-') {
                shift_string_right(work, 1);
                work[0] = '0';
        }

        if (!(op = strpbrk(work, "#><+-&|*/%^"))) {
		if (calculate(work, &value1, &ll_value1, 
		    flags & (HEX_BIAS|LONG_LONG))) { 
			if (flags & LONG_LONG) {
				np->ll_num = ll_value1;
				if (BITS32() && (ll_value1 > 0xffffffff)) 
					np->retflags |= LONG_LONG;
				return TRUE;
			} else {
				np->num = value1;
				return TRUE;
			}
		}
               	goto malformed;
        }

	switch (*op)
        {
        case '+': 
		opcode = OP_ADD; 
		break;

        case '-': 
		opcode = OP_SUB; 
		break;

        case '&': 
		opcode = OP_AND; 
		break;

        case '|': 
		opcode = OP_OR; 
		break;

        case '*': 
		opcode = OP_MUL; 
		break;

        case '%': 
		opcode = OP_MOD; 
		break;

        case '/': 
		opcode = OP_DIV; 
		break;

	case '<': 
		if (*(op+1) != '<')
			goto malformed;
		opcode = OP_SL;
	        break;

	case '>': 
                if (*(op+1) != '>')
                        goto malformed;
                opcode = OP_SR;
	        break;

	case '^':
		opcode = OP_EXOR;
		break;

	case '#':
		opcode = OP_POWER;
		break;
	}

        element1 = &work[0];
	*op = NULLCHAR;
	if ((opcode == OP_SL) || (opcode == OP_SR)) {
		*(op+1) = NULLCHAR;
		element2 = op+2;
	} else 
		element2 = op+1;

        if (strlen(clean_line(element1)) == 0)
                goto malformed;

        if (strlen(clean_line(element2)) == 0)
                goto malformed;

	if ((sp = symbol_search(element1)))
                value1 = ll_value1 = sp->value;
	else {
		if (!calculate(element1, &value1, &ll_value1, 
		    flags & (HEX_BIAS|LONG_LONG)))
			goto malformed;
                if (BITS32() && (ll_value1 > 0xffffffff)) 
                	np->retflags |= LONG_LONG;
	}

        if ((sp = symbol_search(element2)))
                value2 = ll_value2 = sp->value;
        else if (!calculate(element2, &value2, &ll_value2, 
	    	flags & (HEX_BIAS|LONG_LONG)))
		goto malformed;

	if (flags & LONG_LONG) {
		if (BITS32() && (ll_value2 > 0xffffffff)) 
			np->retflags |= LONG_LONG;

                switch (opcode)
                {
                case OP_ADD:
                        np->ll_num = (ll_value1 + ll_value2);
			break;           
                case OP_SUB:
                        np->ll_num = (ll_value1 - ll_value2);
			break;           
                case OP_AND:
                        np->ll_num = (ll_value1 & ll_value2);
			break;           
                case OP_OR:
                        np->ll_num = (ll_value1 | ll_value2);
			break;           
                case OP_MUL:
                        np->ll_num = (ll_value1 * ll_value2);
			break;           
                case OP_DIV:
                        np->ll_num = (ll_value1 / ll_value2);
			break;           
                case OP_MOD:
                        np->ll_num = (ll_value1 % ll_value2);
			break;           
                case OP_SL:
                        np->ll_num = (ll_value1 << ll_value2);
			break;           
                case OP_SR:
                        np->ll_num = (ll_value1 >> ll_value2);
			break;           
                case OP_EXOR:
                        np->ll_num = (ll_value1 ^ ll_value2);
			break;
		case OP_POWER:
			np->ll_num = ll_power(ll_value1, ll_value2);
			break;
                }
	} else {
		switch (opcode)
		{
		case OP_ADD: 
			np->num = (value1 + value2);
			break;
		case OP_SUB:
			np->num = (value1 - value2);
			break;
		case OP_AND: 
			np->num = (value1 & value2);
			break;
		case OP_OR:  
			np->num = (value1 | value2);
			break;
		case OP_MUL: 
			np->num = (value1 * value2);
			break;
		case OP_DIV: 
			np->num = (value1 / value2);
			break;
		case OP_MOD: 
			np->num = (value1 % value2);
			break;
		case OP_SL:  
			np->num = (value1 << value2);
			break;
		case OP_SR:  
			np->num = (value1 >> value2);
			break;
		case OP_EXOR:
			np->num = (value1 ^ value2);
			break;
		case OP_POWER:
			np->num = power(value1, value2);
			break;
		}
	}

	return TRUE;

malformed:
	return FALSE;
}


/*
 *  Take string containing a number, and possibly a multiplier, and calculate
 *  its real value.  The allowable multipliers are k, K, m, M, g and G, for
 *  kilobytes, megabytes and gigabytes.
 */
int
calculate(char *s, ulong *value, ulonglong *llvalue, ulong flags)
{
	ulong factor, bias;
	int errflag;
	int ones_complement;
	ulong localval;
	ulonglong ll_localval;
	struct syment *sp;

	bias = flags & HEX_BIAS;

	if (*s == '~') {
		ones_complement = TRUE;
		s++;
	} else
		ones_complement = FALSE;

        if ((sp = symbol_search(s))) {
		if (flags & LONG_LONG) {
			*llvalue = (ulonglong)sp->value;
			if (ones_complement)
                		*llvalue = ~(*llvalue);
		} else 
                	*value = ones_complement ? ~(sp->value) : sp->value;
		return TRUE;
	}

	factor = 1;
	errflag = 0;

        switch (LASTCHAR(s))
        {
        case 'k':
        case 'K':
                LASTCHAR(s) = NULLCHAR;
                if (IS_A_NUMBER(s))
                        factor = 1024;
		else
			return FALSE;
                break;

        case 'm':
        case 'M':
                LASTCHAR(s) = NULLCHAR;
                if (IS_A_NUMBER(s))
                        factor = (1024*1024);
		else 
			return FALSE;
                break;

        case 'g':
        case 'G':
                LASTCHAR(s) = NULLCHAR;
                if (IS_A_NUMBER(s))
                        factor = (1024*1024*1024);
		else
			return FALSE;
                break;

        default:
		if (!IS_A_NUMBER(s))
			return FALSE;
		break;
        }

	if (flags & LONG_LONG) {
                ll_localval = stoll(s, RETURN_ON_ERROR|bias, &errflag);
                if (errflag)
                        return FALSE;

                if (ones_complement)
                        *llvalue = ~(ll_localval * factor);
                else
                        *llvalue = ll_localval * factor;
	} else {
		localval = stol(s, RETURN_ON_ERROR|bias, &errflag);
		if (errflag)
			return FALSE;

		if (ones_complement)
			*value = ~(localval * factor);
		else
			*value = localval * factor;
	}

	return TRUE;
}


/*
 *  Print a 32-bit or 64-bit number in hexadecimal, decimal, octal and binary,
 *  also showing the bits set if appropriate.
 *  
 */
static void
print_number(struct number_option *np, int bitflag, int longlongflagforce)
{
	int i;
	ulong hibit;
	ulonglong ll_hibit;
        int ccnt;
        ulong mask;
	ulonglong ll_mask;
        char *hdr = "   bits set: ";
        char buf[BUFSIZE];
        int hdrlen;
	int longlongformat;

	longlongformat = longlongflagforce;

	if (!longlongflagforce) {
		if (BITS32()) {
			if (np->retflags & LONG_LONG)
				longlongformat = TRUE;
			if (np->ll_num > 0xffffffff) 
				longlongformat = TRUE;
			else
				np->num = (ulong)np->ll_num;
		} 
	}

	if (longlongformat) {
                ll_hibit = (ulonglong)(1) << ((sizeof(long long)*8)-1);
                
                fprintf(fp, "hexadecimal: %llx  ", np->ll_num);
                if (np->ll_num >= KILOBYTES(1)) {
                        if ((np->ll_num % GIGABYTES(1)) == 0)
                                fprintf(fp, "(%lldGB)", 
					np->ll_num / GIGABYTES(1));
                        else if ((np->ll_num % MEGABYTES(1)) == 0)
                                fprintf(fp, "(%lldMB)", 
					np->ll_num / MEGABYTES(1));
                        else if ((np->ll_num % KILOBYTES(1)) == 0)
                                fprintf(fp, "(%lldKB)",
					 np->ll_num / KILOBYTES(1));
                }
                fprintf(fp, "\n");

                fprintf(fp, "    decimal: %llu  ", np->ll_num);
                if ((long long)np->ll_num < 0)
                        fprintf(fp, "(%lld)\n", (long long)np->ll_num);
                else
                        fprintf(fp, "\n");
                fprintf(fp, "      octal: %llo\n", np->ll_num);
                fprintf(fp, "     binary: ");
                for(i = 0, ll_mask = np->ll_num; i < (sizeof(long long)*8); 
		    i++, ll_mask <<= 1)
                        if (ll_mask & ll_hibit)
                                fprintf(fp, "1");
                        else
                                fprintf(fp, "0");
                fprintf(fp,"\n");
	} else {
		hibit = (ulong)(1) << ((sizeof(long)*8)-1);
	
	        fprintf(fp, "hexadecimal: %lx  ", np->num);
	        if (np->num >= KILOBYTES(1)) {
	                if ((np->num % GIGABYTES(1)) == 0)
	                        fprintf(fp, "(%ldGB)", np->num / GIGABYTES(1));
	                else if ((np->num % MEGABYTES(1)) == 0)
	                        fprintf(fp, "(%ldMB)", np->num / MEGABYTES(1));
	                else if ((np->num % KILOBYTES(1)) == 0)
	                        fprintf(fp, "(%ldKB)", np->num / KILOBYTES(1));
	        }
	        fprintf(fp, "\n");
	
	        fprintf(fp, "    decimal: %lu  ", np->num);
		if ((long)np->num < 0)
	                fprintf(fp, "(%ld)\n", (long)np->num);
	        else
	                fprintf(fp, "\n");
	        fprintf(fp, "      octal: %lo\n", np->num);
	        fprintf(fp, "     binary: ");
	        for(i = 0, mask = np->num; i < (sizeof(long)*8); 
		    i++, mask <<= 1)
	                if (mask & hibit)
	                        fprintf(fp, "1");
	                else
	                        fprintf(fp, "0");
	        fprintf(fp,"\n");
	}

	if (!bitflag)
		return;

	hdrlen = strlen(hdr);
	ccnt = hdrlen;
	fprintf(fp, "%s", hdr);

	if (longlongformat) {
	        for (i = 63; i >= 0; i--) {
	                ll_mask = (ulonglong)(1) << i;
	                if (np->ll_num & ll_mask) {
	                        sprintf(buf, "%d ", i);
	                        fprintf(fp, "%s", buf);
	                        ccnt += strlen(buf);
	                        if (ccnt >= 77) {
	                                fprintf(fp, "\n");
	                                INDENT(strlen(hdr));
	                                ccnt = hdrlen;
	                        }
	                }
	        }
	} else {
	        for (i = BITS()-1; i >= 0; i--) {
	                mask = (ulong)(1) << i;
	                if (np->num & mask) {
	                        sprintf(buf, "%d ", i);
	                        fprintf(fp, "%s", buf);
	                        ccnt += strlen(buf);
	                        if (ccnt >= 77) {
	                                fprintf(fp, "\n");
	                                INDENT(strlen(hdr));
	                                ccnt = hdrlen;
	                        }
	                }
	        }
	}
        fprintf(fp, "\n");
}


/*
 *  Display the contents of a linked list.  Minimum requirements are a starting
 *  address, typically of a structure which contains the "next" list entry at 
 *  some offset into the structure.  The default offset is zero bytes, and need
 *  not be entered if that's the case.  Otherwise a number argument that's not 
 *  a kernel *  virtual address will be understood to be the offset.  
 *  Alternatively the offset may be entered in "struct.member" format.  Each 
 *  item in the list is dumped, and the list will be considered terminated upon
 *  encountering a "next" value that is:
 *
 *     a NULL pointer. 
 *     a pointer to the starting address. 
 *     a pointer to the entry pointed to by the starting address. 
 *     a pointer to the structure itself.
 *     a pointer to the value specified with the "-e ending_addr" option.
 *
 *  If the structures are linked using list_head structures, the -h or -H 
 *  options must be used.  In that case, the "start" address is:
 *  a pointer to the structure that contains the list_head structure (-h),
 *  or a pointer to a LIST_HEAD() structure (-H).
 *
 *  Given that the contents of the structures containing the next pointers
 *  often contain useful data, the "-s structname" also prints each structure
 *  in the list. 
 *
 *  By default, the list members are hashed to guard against duplicate entries
 *  causing the list to wrap back upon itself.
 *
 *  WARNING: There's an inordinate amount of work parsing arguments below
 *  in order to maintain backwards compatibility re: not having to use -o,
 *  which gets sticky with zero-based kernel virtual address space.
 */

void
cmd_list(void)
{
	int c;
	long head_member_offset = 0; /* offset for head like denty.d_subdirs */
	struct list_data list_data, *ld;
	struct datatype_member struct_member, *sm;
	struct syment *sp;
	ulong value, struct_list_offset; 

	sm = &struct_member;
	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	struct_list_offset = 0;

	while ((c = getopt(argcnt, args, "BHhrs:S:e:o:O:xdl:")) != EOF) {
                switch(c)
		{
		case 'B':
			ld->flags |= LIST_BRENT_ALGO;
			break;
		case 'H':
			ld->flags |= LIST_HEAD_FORMAT;
			ld->flags |= LIST_HEAD_POINTER;
			break;

		case 'h':
			ld->flags |= LIST_HEAD_FORMAT;
			break;

		case 'r':
			ld->flags |= LIST_HEAD_REVERSE;
			break;

		case 's':
		case 'S':
			if (ld->structname_args++ == 0)
				hq_open();
			hq_enter((ulong)optarg);
			ld->flags |= (c == 's') ? LIST_PARSE_MEMBER : LIST_READ_MEMBER;
			if (count_bits_long(ld->flags & (LIST_PARSE_MEMBER|LIST_READ_MEMBER)) > 1)
				error(FATAL, "-S and -s options are mutually exclusive\n");
			break;

		case 'l':
                        if (IS_A_NUMBER(optarg))
                                struct_list_offset = stol(optarg,
                                        FAULT_ON_ERROR, NULL);
                        else if (arg_to_datatype(optarg,
                                sm, RETURN_ON_ERROR) > 1)
                                struct_list_offset = sm->member_offset;
			else
				error(FATAL, "invalid -l option: %s\n", 
					optarg);
			break;

		case 'O':
			if (ld->flags & LIST_HEAD_OFFSET_ENTERED)
				error(FATAL, "offset value %d (0x%lx) already entered\n",
					head_member_offset, head_member_offset);
			else if (IS_A_NUMBER(optarg))
				head_member_offset = stol(optarg, FAULT_ON_ERROR, NULL);
			else if (arg_to_datatype(optarg, sm, RETURN_ON_ERROR) > 1)
				head_member_offset = sm->member_offset;
			else
				error(FATAL, "invalid -O argument: %s\n", optarg);

			ld->flags |= LIST_HEAD_OFFSET_ENTERED;
			break;

		case 'o':
			if (ld->flags & LIST_OFFSET_ENTERED) 
                               error(FATAL,
                                "offset value %d (0x%lx) already entered\n",
                                        ld->member_offset, ld->member_offset);
			else if (IS_A_NUMBER(optarg)) 
				ld->member_offset = stol(optarg, 
					FAULT_ON_ERROR, NULL);
			else if (arg_to_datatype(optarg, 
				sm, RETURN_ON_ERROR) > 1) 
				ld->member_offset = sm->member_offset;
			else
				error(FATAL, "invalid -o argument: %s\n",
					optarg);

			ld->flags |= LIST_OFFSET_ENTERED; 
			break;

		case 'e':
			ld->end = htol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'x':
			if (ld->flags & LIST_STRUCT_RADIX_10)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			ld->flags |= LIST_STRUCT_RADIX_16;
			break;

		case 'd':
			if (ld->flags & LIST_STRUCT_RADIX_16)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			ld->flags |= LIST_STRUCT_RADIX_10;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (args[optind] && args[optind+1] && args[optind+2]) {
		error(INFO, "too many arguments\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (ld->structname_args) {
		ld->structname = (char **)GETBUF(sizeof(char *) * ld->structname_args);
		retrieve_list((ulong *)ld->structname, ld->structname_args); 
		hq_close(); 
		ld->struct_list_offset = struct_list_offset;
	} else if (struct_list_offset) {
		error(INFO, "-l option can only be used with -s or -S option\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	while (args[optind]) {
		if (strstr(args[optind], ".") &&
		    arg_to_datatype(args[optind], sm, RETURN_ON_ERROR) > 1) {
			if (ld->flags & LIST_OFFSET_ENTERED)
				error(FATAL, 
			           "offset value %ld (0x%lx) already entered\n",
					ld->member_offset, ld->member_offset);
			ld->member_offset = sm->member_offset;
			ld->flags |= LIST_OFFSET_ENTERED;
		} else {
			/* 
			 *  Do an inordinate amount of work to avoid -o...
			 *
			 *  OK, if it's a symbol, then it has to be a start.
			 */
			if ((sp = symbol_search(args[optind]))) {
				if (ld->flags & LIST_START_ENTERED) 
                                        error(FATAL,
                                            "list start already entered\n");
                                ld->start = sp->value;
                                ld->flags |= LIST_START_ENTERED;
				goto next_arg;
			}

			/*
			 *  If it's not a symbol nor a number, bail out if it
			 *  cannot be evaluated as a start address.
			 */
			if (!IS_A_NUMBER(args[optind])) {	
				if (can_eval(args[optind])) {
                        		value = eval(args[optind], FAULT_ON_ERROR, NULL);
					if (IS_KVADDR(value)) {
                               			if (ld->flags & LIST_START_ENTERED)
                                        		error(FATAL,
                                            		    "list start already entered\n");
                                		ld->start = value;
                                		ld->flags |= LIST_START_ENTERED;
						goto next_arg;
					}
				}
				
				error(FATAL, "invalid argument: %s\n",
                                	args[optind]);
			}

			/*
			 *  If the start is known, it's got to be an offset.
			 */
                        if (ld->flags & LIST_START_ENTERED) {
                                value = stol(args[optind], FAULT_ON_ERROR,
                                        NULL);
                                ld->member_offset = value;
                                ld->flags |= LIST_OFFSET_ENTERED;
                                break;
                        }

			/*
			 *  If the offset is known, or there's no subsequent
                         *  argument, then it's got to be a start.
			 */
			if ((ld->flags & LIST_OFFSET_ENTERED) ||
			    !args[optind+1]) {
				value = htol(args[optind], FAULT_ON_ERROR, 
					NULL);
				if (!IS_KVADDR(value))
					error(FATAL, 
				        "invalid kernel virtual address: %s\n",
						args[optind]);
                                ld->start = value;
                                ld->flags |= LIST_START_ENTERED;
				break;
			}

			/*
			 *  Neither start nor offset has been entered, and
			 *  it's a number.  Look ahead to the next argument.
			 *  If it's a symbol, then this must be an offset.
			 */
			if ((sp = symbol_search(args[optind+1]))) {
                                value = stol(args[optind], FAULT_ON_ERROR,
                                        NULL);
                                ld->member_offset = value;
                                ld->flags |= LIST_OFFSET_ENTERED;
                                goto next_arg;
			} else if ((!IS_A_NUMBER(args[optind+1]) &&
				!can_eval(args[optind+1])) &&
				!strstr(args[optind+1], "."))
				error(FATAL, "symbol not found: %s\n",
                                        args[optind+1]);
			/*
			 *  Crunch time.  We've got two numbers.  If they're
			 *  both ambigous we must have zero-based kernel 
			 *  virtual address space.
			 */
			if (COMMON_VADDR_SPACE() &&
			    AMBIGUOUS_NUMBER(args[optind]) &&
			    AMBIGUOUS_NUMBER(args[optind+1])) {
				error(INFO, 
                     "ambiguous arguments: \"%s\" and \"%s\": -o is required\n",
					args[optind], args[optind+1]);
				cmd_usage(pc->curcmd, SYNOPSIS);
			}

			if (hexadecimal_only(args[optind], 0)) {
				value = htol(args[optind], FAULT_ON_ERROR, 
					NULL);
                                if (IS_KVADDR(value)) {
                                	ld->start = value;
                                	ld->flags |= LIST_START_ENTERED;
					goto next_arg;
				}
			} 
			value = stol(args[optind], FAULT_ON_ERROR, NULL);
                        ld->member_offset = value;
                        ld->flags |= LIST_OFFSET_ENTERED;
		}
next_arg:
		optind++;
	}

	if (!(ld->flags & LIST_START_ENTERED)) {
		error(INFO, "starting address required\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if ((ld->flags & LIST_OFFSET_ENTERED) && ld->struct_list_offset) {
		error(INFO, "-l and -o are mutually exclusive\n");
                cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (ld->flags & LIST_HEAD_FORMAT) {
		ld->list_head_offset = ld->member_offset;
		if (ld->flags & LIST_HEAD_REVERSE)
			ld->member_offset = sizeof(void *);
		else
			ld->member_offset = 0;
		if (ld->flags & LIST_HEAD_POINTER) {
			if (!ld->end)
				ld->end = ld->start;
			readmem(ld->start + ld->member_offset, KVADDR, &ld->start,
				sizeof(void *), "LIST_HEAD contents", FAULT_ON_ERROR);
			if (ld->start == ld->end) {
				fprintf(fp, "(empty)\n");
				return;
			}
		} else {
			if (ld->flags & LIST_HEAD_OFFSET_ENTERED) {
				if (!ld->end)
					ld->end = ld->start + head_member_offset;
				readmem(ld->start + head_member_offset, KVADDR, &ld->start,
					sizeof(void *), "LIST_HEAD contents", FAULT_ON_ERROR);
				if (ld->start == ld->end) {
					fprintf(fp, "(empty)\n");
					return;
				}
			} else
				ld->start += ld->list_head_offset;
		}
	}

	ld->flags &= ~(LIST_OFFSET_ENTERED|LIST_START_ENTERED);
	ld->flags |= VERBOSE;

	if (ld->flags & LIST_BRENT_ALGO)
		c = do_list_no_hash(ld);
	else {
		hq_open();
		c = do_list(ld);
		hq_close();
	}

        if (ld->structname_args)
		FREEBUF(ld->structname);
}

void
dump_struct_members_fast(struct req_entry *e, int radix, ulong p)
{
	unsigned int i;
	char b[BUFSIZE];

	if (!(e && IS_KVADDR(p)))
		return;

	if (!radix)
		radix = *gdb_output_radix;

	for (i = 0; i < e->count; i++) {
		if (0 < e->width[i] && (e->width[i] <= 8 || e->is_str[i])) {
			print_value(e, i, p, e->is_ptr[i] ? 16 : radix);
		} else if (e->width[i] == 0 || e->width[i] > 8) {
			snprintf(b, BUFSIZE, "%s.%s", e->name, e->member[i]);
			dump_struct_member(b, p, radix);
		}
	}
}

struct req_entry *
fill_member_offsets(char *arg)
{
	int j;
	char *p, m;
	struct req_entry *e;
	char buf[BUFSIZE];

	if (!(arg && *arg))
		return NULL;

	j = count_chars(arg, ',') + 1;
	e = (struct req_entry *)GETBUF(sizeof(*e));

	e->arg = GETBUF(strlen(arg + 1));
	strcpy(e->arg, arg);

	m = ((p = strchr(e->arg, '.')) != NULL);
	if (!p++)
		p = e->arg + strlen(e->arg) + 1;

	e->name = GETBUF(p - e->arg);
	strncpy(e->name, e->arg, p - e->arg - 1);

	if (!m)
		return e;

	e->count  = count_chars(p, ',') + 1;
	e->width  = (ulong *)GETBUF(e->count * sizeof(ulong));
	e->is_ptr = (int *)GETBUF(e->count * sizeof(int));
	e->is_str = (int *)GETBUF(e->count * sizeof(int));
	e->member = (char **)GETBUF(e->count * sizeof(char *));
	e->offset = (ulong *)GETBUF(e->count * sizeof(ulong));

	replace_string(p, ",", ' ');
	parse_line(p, e->member);

	for (j = 0; j < e->count; j++) {
		e->offset[j] = MEMBER_OFFSET(e->name, e->member[j]);
		if (e->offset[j] == INVALID_OFFSET)
			e->offset[j] = ANON_MEMBER_OFFSET(e->name, e->member[j]);
		if (e->offset[j] == INVALID_OFFSET)
			error(FATAL, "Can't get offset of '%s.%s'\n",
				e->name, e->member[j]);

		e->is_ptr[j] = MEMBER_TYPE(e->name, e->member[j]) == TYPE_CODE_PTR;
		e->is_str[j] = is_string(e->name, e->member[j]);

		/* Dirty hack for obtaining size of particular field */
		snprintf(buf, BUFSIZE, "%s + 1", e->member[j]);
		e->width[j] = ANON_MEMBER_OFFSET(e->name, buf) - e->offset[j];
	}

	return e;
}

static void
print_value(struct req_entry *e, unsigned int i, ulong addr, unsigned int radix)
{
	union { uint64_t v64; uint32_t v32;
		uint16_t v16; uint8_t v8;
	} v;
	char buf[BUFSIZE];
	struct syment *sym;

	addr += e->offset[i];

	/* Read up to 8 bytes, counters, pointers, etc. */
	if (e->width[i] <= 8 && !readmem(addr, KVADDR, &v, e->width[i],
	    "structure value", RETURN_ON_ERROR | QUIET)) {
		error(INFO, "cannot access member: %s at %lx\n", e->member[i], addr);
		return;
	}
	snprintf(buf, BUFSIZE, "  %%s = %s%%%s%s",
		 (radix == 16 ? "0x" : ""),
		 (e->width[i] == 8 ? "l" : ""),
		 (radix == 16 ? "x" : "u" )
		);

	switch (e->width[i]) {
		case 1: fprintf(fp, buf, e->member[i], v.v8); break;
		case 2: fprintf(fp, buf, e->member[i], v.v16); break;
		case 4: fprintf(fp, buf, e->member[i], v.v32); break;
		case 8: fprintf(fp, buf, e->member[i], v.v64); break;
	}


	if (e->is_str[i]) {
		if (e->is_ptr[i]) {
			read_string(v.v64, buf, BUFSIZE);
			fprintf(fp, "  \"%s\"", buf);
		} else {
			read_string(addr, buf, e->width[i]);
			fprintf(fp, "  %s = \"%s\"", e->member[i], buf);
		}
	} else if ((sym = value_search(v.v64, 0)) && is_symbol_text(sym))
		fprintf(fp, " <%s>", sym->name);

	fprintf(fp, "\n");
}

/*
 *  Does the work for cmd_list() and any other function that requires the
 *  contents of a linked list.  See cmd_list description above for details.
 */
int
do_list(struct list_data *ld)
{
	ulong next, last, first, offset;
	ulong searchfor, readflag;
	int i, count, others, close_hq_on_return;
	unsigned int radix;
	struct req_entry **e = NULL;

	if (CRASHDEBUG(1)) {
		others = 0;
		console("             flags: %lx (", ld->flags);
		if (ld->flags & VERBOSE)
			console("%sVERBOSE", others++ ? "|" : "");
		if (ld->flags & LIST_OFFSET_ENTERED)
			console("%sLIST_OFFSET_ENTERED", others++ ? "|" : "");
		if (ld->flags & LIST_START_ENTERED)
			console("%sLIST_START_ENTERED", others++ ? "|" : "");
		if (ld->flags & LIST_HEAD_FORMAT)
			console("%sLIST_HEAD_FORMAT", others++ ? "|" : "");
		if (ld->flags & LIST_HEAD_POINTER)
			console("%sLIST_HEAD_POINTER", others++ ? "|" : "");
		if (ld->flags & RETURN_ON_DUPLICATE)
			console("%sRETURN_ON_DUPLICATE", others++ ? "|" : "");
		if (ld->flags & RETURN_ON_LIST_ERROR)
			console("%sRETURN_ON_LIST_ERROR", others++ ? "|" : "");
		if (ld->flags & RETURN_ON_LIST_ERROR)
			console("%sRETURN_ON_LIST_ERROR", others++ ? "|" : "");
		if (ld->flags & LIST_STRUCT_RADIX_10)
			console("%sLIST_STRUCT_RADIX_10", others++ ? "|" : "");
		if (ld->flags & LIST_STRUCT_RADIX_16)
			console("%sLIST_STRUCT_RADIX_16", others++ ? "|" : "");
		if (ld->flags & LIST_ALLOCATE)
			console("%sLIST_ALLOCATE", others++ ? "|" : "");
		if (ld->flags & LIST_CALLBACK)
			console("%sLIST_CALLBACK", others++ ? "|" : "");
		if (ld->flags & CALLBACK_RETURN)
			console("%sCALLBACK_RETURN", others++ ? "|" : "");
		console(")\n");
		console("             start: %lx\n", ld->start);
		console("     member_offset: %ld\n", ld->member_offset);
		console("  list_head_offset: %ld\n", ld->list_head_offset);
		console("               end: %lx\n", ld->end);
		console("         searchfor: %lx\n", ld->searchfor);
		console("   structname_args: %lx\n", ld->structname_args);
		if (!ld->structname_args)
			console("        structname: (unused)\n");
		for (i = 0; i < ld->structname_args; i++)	
			console("     structname[%d]: %s\n", i, ld->structname[i]);
		console("            header: %s\n", ld->header);
		console("          list_ptr: %lx\n", (ulong)ld->list_ptr);
		console("     callback_func: %lx\n", (ulong)ld->callback_func);
		console("     callback_data: %lx\n", (ulong)ld->callback_data);
		console("struct_list_offset: %lx\n", ld->struct_list_offset);
	}

	count = 0;
	searchfor = ld->searchfor;
	ld->searchfor = 0;
	if (ld->flags & LIST_STRUCT_RADIX_10)
		radix = 10;
	else if (ld->flags & LIST_STRUCT_RADIX_16)
		radix = 16;
	else	
		radix = 0;
	next = ld->start;

	close_hq_on_return = FALSE;
	if (ld->flags & LIST_ALLOCATE) {
		if (!hq_is_open()) {
			hq_open();
			close_hq_on_return = TRUE;
		} else if (hq_is_inuse()) {
			error(ld->flags & RETURN_ON_LIST_ERROR ? INFO : FATAL,
				"\ndo_list: hash queue is in use?\n");
			return -1;
		}
	}

	readflag = ld->flags & RETURN_ON_LIST_ERROR ? 
		(RETURN_ON_ERROR|QUIET) : FAULT_ON_ERROR;

	if (!readmem(next + ld->member_offset, KVADDR, &first, sizeof(void *),
            "first list entry", readflag)) {
                error(INFO, "\ninvalid list entry: %lx\n", next);
		if (close_hq_on_return)
			hq_close();
		return -1;
	}

	if (ld->header)
		fprintf(fp, "%s", ld->header);

	offset = ld->list_head_offset + ld->struct_list_offset;

	if (ld->structname && (ld->flags & LIST_READ_MEMBER)) {
		e = (struct req_entry **)GETBUF(sizeof(*e) * ld->structname_args);
		for (i = 0; i < ld->structname_args; i++)
			e[i] = fill_member_offsets(ld->structname[i]);
	}

	while (1) {
		if (ld->flags & VERBOSE) {
			fprintf(fp, "%lx\n", next - ld->list_head_offset);

			if (ld->structname) {
				for (i = 0; i < ld->structname_args; i++) {
					switch (count_chars(ld->structname[i], '.'))
					{
					case 0:
						dump_struct(ld->structname[i],
							next - offset, radix);
						break;
					default:
						if (ld->flags & LIST_PARSE_MEMBER)
							dump_struct_members(ld, i, next);
						else if (ld->flags & LIST_READ_MEMBER)
							dump_struct_members_fast(e[i],
								radix, next - offset);
						break;
					}
				}
			}
		}

                if (next && !hq_enter(next - ld->list_head_offset)) {
			if (ld->flags & 
			    (RETURN_ON_DUPLICATE|RETURN_ON_LIST_ERROR)) {
                        	error(INFO, "\nduplicate list entry: %lx\n", 
					next);
				if (close_hq_on_return)
					hq_close();
				return -1;
			}
                        error(FATAL, "\nduplicate list entry: %lx\n", next);
		}

		if ((searchfor == next) || 
		    (searchfor == (next - ld->list_head_offset)))
			ld->searchfor = searchfor;

		count++;
                last = next;

		if ((ld->flags & LIST_CALLBACK) &&
		    ld->callback_func((void *)(next - ld->list_head_offset),
		    ld->callback_data) && (ld->flags & CALLBACK_RETURN))
			break;

                if (!readmem(next + ld->member_offset, KVADDR, &next, 
		    sizeof(void *), "list entry", readflag)) {
			error(INFO, "\ninvalid list entry: %lx\n", next);
			if (close_hq_on_return)
				hq_close();
			return -1;
		}

		if (next == 0) {
			if (ld->flags & LIST_HEAD_FORMAT) {
				error(INFO, "\ninvalid list entry: 0\n");
				if (close_hq_on_return)
					hq_close();
				return -1;
			}
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx\n", next);
			break;
		}

		if (next == ld->end) {
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx == end:%lx\n", 
					next, ld->end);
			break;
		}

		if (next == ld->start) {
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx == start:%lx\n", 
					next, ld->start);
			break;
		}

		if (next == last) {
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx == last:%lx\n", 
					next, last);
			break;
		}

		if ((next == first) && (count != 1)) {
			if (CRASHDEBUG(1))
		      console("do_list end: next:%lx == first:%lx (count %d)\n",
				next, last, count);
			break;
		}
	}

	if (CRASHDEBUG(1))
		console("do_list count: %d\n", count);

	if (ld->flags & LIST_ALLOCATE) {
		ld->list_ptr = (ulong *)GETBUF(count * sizeof(void *));
		count = retrieve_list(ld->list_ptr, count);
		if (close_hq_on_return)
			hq_close();
	}

	return count;
}

static void 
do_list_debug_entry(struct list_data *ld)
{
	int i, others;

	if (CRASHDEBUG(1)) {
		others = 0;
		console("             flags: %lx (", ld->flags);
		if (ld->flags & VERBOSE)
			console("%sVERBOSE", others++ ? "|" : "");
		if (ld->flags & LIST_OFFSET_ENTERED)
			console("%sLIST_OFFSET_ENTERED", others++ ? "|" : "");
		if (ld->flags & LIST_START_ENTERED)
			console("%sLIST_START_ENTERED", others++ ? "|" : "");
		if (ld->flags & LIST_HEAD_FORMAT)
			console("%sLIST_HEAD_FORMAT", others++ ? "|" : "");
		if (ld->flags & LIST_HEAD_POINTER)
			console("%sLIST_HEAD_POINTER", others++ ? "|" : "");
		if (ld->flags & RETURN_ON_DUPLICATE)
			console("%sRETURN_ON_DUPLICATE", others++ ? "|" : "");
		if (ld->flags & RETURN_ON_LIST_ERROR)
			console("%sRETURN_ON_LIST_ERROR", others++ ? "|" : "");
		if (ld->flags & RETURN_ON_LIST_ERROR)
			console("%sRETURN_ON_LIST_ERROR", others++ ? "|" : "");
		if (ld->flags & LIST_STRUCT_RADIX_10)
			console("%sLIST_STRUCT_RADIX_10", others++ ? "|" : "");
		if (ld->flags & LIST_STRUCT_RADIX_16)
			console("%sLIST_STRUCT_RADIX_16", others++ ? "|" : "");
		if (ld->flags & LIST_ALLOCATE)
			console("%sLIST_ALLOCATE", others++ ? "|" : "");
		if (ld->flags & LIST_CALLBACK)
			console("%sLIST_CALLBACK", others++ ? "|" : "");
		if (ld->flags & CALLBACK_RETURN)
			console("%sCALLBACK_RETURN", others++ ? "|" : "");
		console(")\n");
		console("             start: %lx\n", ld->start);
		console("     member_offset: %ld\n", ld->member_offset);
		console("  list_head_offset: %ld\n", ld->list_head_offset);
		console("               end: %lx\n", ld->end);
		console("         searchfor: %lx\n", ld->searchfor);
		console("   structname_args: %lx\n", ld->structname_args);
		if (!ld->structname_args)
			console("        structname: (unused)\n");
		for (i = 0; i < ld->structname_args; i++)
			console("     structname[%d]: %s\n", i, ld->structname[i]);
		console("            header: %s\n", ld->header);
		console("          list_ptr: %lx\n", (ulong)ld->list_ptr);
		console("     callback_func: %lx\n", (ulong)ld->callback_func);
		console("     callback_data: %lx\n", (ulong)ld->callback_data);
		console("struct_list_offset: %lx\n", ld->struct_list_offset);
	}
}


static void 
do_list_output_struct(struct list_data *ld, ulong next, ulong offset,
				  unsigned int radix, struct req_entry **e)
{
	int i;

	for (i = 0; i < ld->structname_args; i++) {
		switch (count_chars(ld->structname[i], '.'))
		{
			case 0:
				dump_struct(ld->structname[i],
					    next - offset, radix);
				break;
			default:
				if (ld->flags & LIST_PARSE_MEMBER)
					dump_struct_members(ld, i, next);
				else if (ld->flags & LIST_READ_MEMBER)
					dump_struct_members_fast(e[i],
						 radix, next - offset);
				break;
		}
	}
}

static int 
do_list_no_hash_readmem(struct list_data *ld, ulong *next_ptr,
				   ulong readflag)
{
	if (!readmem(*next_ptr + ld->member_offset, KVADDR, next_ptr,
		     sizeof(void *), "list entry", readflag)) {
		error(INFO, "\ninvalid list entry: %lx\n", *next_ptr);
		return -1;
	}
	return 0;
}

static ulong brent_x; /* tortoise */
static ulong brent_y; /* hare */
static ulong brent_r; /* power */
static ulong brent_lambda; /* loop length */
static ulong brent_mu; /* distance to start of loop */
static ulong brent_loop_detect;
static ulong brent_loop_exit;
/*
 * 'ptr': representative of x or y; modified on return
 */
static int 
brent_f(ulong *ptr, struct list_data *ld, ulong readflag)
{
       return do_list_no_hash_readmem(ld, ptr, readflag);
}

/*
 * Similar to do_list() but without the hash_table or LIST_ALLOCATE.
 * Useful for the 'list' command and other callers needing faster list
 * enumeration.
 */
int
do_list_no_hash(struct list_data *ld)
{
	ulong next, last, first, offset;
	ulong searchfor, readflag;
	int i, count, ret;
	unsigned int radix;
	struct req_entry **e = NULL;

	do_list_debug_entry(ld);

	count = 0;
	searchfor = ld->searchfor;
	ld->searchfor = 0;
	if (ld->flags & LIST_STRUCT_RADIX_10)
		radix = 10;
	else if (ld->flags & LIST_STRUCT_RADIX_16)
		radix = 16;
	else
		radix = 0;
	next = ld->start;

	readflag = ld->flags & RETURN_ON_LIST_ERROR ?
		(RETURN_ON_ERROR|QUIET) : FAULT_ON_ERROR;

	if (!readmem(next + ld->member_offset, KVADDR, &first, sizeof(void *),
            "first list entry", readflag)) {
                error(INFO, "\ninvalid list entry: %lx\n", next);
		return -1;
	}

	if (ld->header)
		fprintf(fp, "%s", ld->header);

	offset = ld->list_head_offset + ld->struct_list_offset;

	if (ld->structname && (ld->flags & LIST_READ_MEMBER)) {
		e = (struct req_entry **)GETBUF(sizeof(*e) * ld->structname_args);
		for (i = 0; i < ld->structname_args; i++)
			e[i] = fill_member_offsets(ld->structname[i]);
	}

	brent_loop_detect = brent_loop_exit = 0;
	brent_lambda = 0;
	brent_r = 2;
	brent_x = brent_y = next;
	ret = brent_f(&brent_y, ld, readflag);
	if (ret == -1)
		return -1;
	while (1) {
		if (!brent_loop_detect && ld->flags & VERBOSE) {
			fprintf(fp, "%lx\n", next - ld->list_head_offset);
			if (ld->structname) {
				do_list_output_struct(ld, next, offset, radix, e);
			}
		}

                if (next && brent_loop_exit) {
			if (ld->flags &
			    (RETURN_ON_DUPLICATE|RETURN_ON_LIST_ERROR)) {
				error(INFO, "\nduplicate list entry: %lx\n",
					brent_x);
				return -1;
			}
			error(FATAL, "\nduplicate list entry: %lx\n", brent_x);
		}

		if ((searchfor == next) ||
		    (searchfor == (next - ld->list_head_offset)))
			ld->searchfor = searchfor;

		count++;
                last = next;

		if ((ld->flags & LIST_CALLBACK) &&
		    ld->callback_func((void *)(next - ld->list_head_offset),
		    ld->callback_data) && (ld->flags & CALLBACK_RETURN))
			break;

		ret = do_list_no_hash_readmem(ld, &next, readflag);
		if (ret == -1)
			return -1;

		if (!brent_loop_detect) {
			if (count > 1 && brent_x == brent_y) {
				brent_loop_detect = 1;
				error(INFO, "loop detected, loop length: %ld\n", brent_lambda);
				/* reset x and y to start; advance y loop length */
				brent_mu = 0;
				brent_x = brent_y = ld->start;
				while (brent_lambda--) {
					ret = brent_f(&brent_y, ld, readflag);
					if (ret == -1)
						return -1;
				}
			} else {
				if (brent_r == brent_lambda) {
					brent_x = brent_y;
					brent_r *= 2;
					brent_lambda = 0;
				}
				brent_y = next;
				brent_lambda++;
			}
		} else {
			if (!brent_loop_exit && brent_x == brent_y) {
				brent_loop_exit = 1;
				error(INFO, "length from start to loop: %lx",
					brent_mu);
			} else {
				ret = brent_f(&brent_x, ld, readflag);
				if (ret == -1)
					return -1;
				ret = brent_f(&brent_y, ld, readflag);
				if (ret == -1)
					return -1;
				brent_mu++;
			}
		}

		if (next == 0) {
			if (ld->flags & LIST_HEAD_FORMAT) {
				error(INFO, "\ninvalid list entry: 0\n");
				return -1;
			}
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx\n", next);

			break;
		}

		if (next == ld->end) {
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx == end:%lx\n",
					next, ld->end);
			break;
		}

		if (next == ld->start) {
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx == start:%lx\n",
					next, ld->start);
			break;
		}

		if (next == last) {
			if (CRASHDEBUG(1))
				console("do_list end: next:%lx == last:%lx\n",
					next, last);
			break;
		}

		if ((next == first) && (count != 1)) {
			if (CRASHDEBUG(1))
		      console("do_list end: next:%lx == first:%lx (count %d)\n",
				next, last, count);
			break;
		}
	}

	if (CRASHDEBUG(1))
		console("do_list count: %d\n", count);

	return count;
}

/*
 *  Issue a dump_struct_member() call for one or more structure
 *  members.  Multiple members are passed in a comma-separated
 *  list using the the format:  
 *
 *            struct.member1,member2,member3
 */
void
dump_struct_members(struct list_data *ld, int idx, ulong next)
{
	int i, argc;
	char *p1, *p2;
	char *structname, *members;
	char *arglist[MAXARGS];
	unsigned int radix;

	if (ld->flags & LIST_STRUCT_RADIX_10)
		radix = 10;
	else if (ld->flags & LIST_STRUCT_RADIX_16)
		radix = 16;
	else
		radix = 0;

	structname = GETBUF(strlen(ld->structname[idx])+1);
	members = GETBUF(strlen(ld->structname[idx])+1);

	strcpy(structname, ld->structname[idx]);
	p1 = strstr(structname, ".") + 1;

	p2 = strstr(ld->structname[idx], ".") + 1;
	strcpy(members, p2);
	replace_string(members, ",", ' ');
	argc = parse_line(members, arglist);

	for (i = 0; i < argc; i++) {
		*p1 = NULLCHAR;
		strcat(structname, arglist[i]);
 		dump_struct_member(structname, 
			next - ld->list_head_offset - ld->struct_list_offset, radix);
	}

	FREEBUF(structname);
	FREEBUF(members);
}

#define RADIXTREE_REQUEST (0x1)
#define RBTREE_REQUEST    (0x2)
#define XARRAY_REQUEST    (0x4)
#define MAPLE_REQUEST     (0x8)

void
cmd_tree()
{
	int c, type_flag, others;
	long root_offset;
	struct tree_data tree_data, *td;
	struct datatype_member struct_member, *sm;
	struct syment *sp;
	ulong value;
	char *type_name = NULL;

	type_flag = 0;
	root_offset = 0;
	sm = &struct_member;
	td = &tree_data;
	BZERO(td, sizeof(struct tree_data));

	while ((c = getopt(argcnt, args, "xdt:r:o:s:S:plNv")) != EOF) {
		switch (c)
		{
		case 't':
			if (type_flag & (RADIXTREE_REQUEST|RBTREE_REQUEST|XARRAY_REQUEST|MAPLE_REQUEST)) {
				error(INFO, "multiple tree types may not be entered\n");
				cmd_usage(pc->curcmd, SYNOPSIS);
			}

			if (STRNEQ(optarg, "ra"))
				if (MEMBER_EXISTS("radix_tree_root", "xa_head")) {
					type_flag = XARRAY_REQUEST;
					type_name = "Xarrays";
				} else {
					type_flag = RADIXTREE_REQUEST;
					type_name = "radix trees";
				}
			else if (STRNEQ(optarg, "rb")) {
				type_flag = RBTREE_REQUEST;
				type_name = "rbtrees";
			} else if (STRNEQ(optarg, "x")) {
				type_flag = XARRAY_REQUEST;
				type_name = "Xarrays";
			} else if (STRNEQ(optarg, "m")) {
				type_flag = MAPLE_REQUEST;
				type_name = "maple trees";
			} else {
				error(INFO, "invalid tree type: %s\n", optarg);
				cmd_usage(pc->curcmd, SYNOPSIS);
			}
				
			break;

		case 'l':
			td->flags |= TREE_LINEAR_ORDER;
			break;

		case 'r':
			if (td->flags & TREE_ROOT_OFFSET_ENTERED) 
				error(FATAL,
					"root offset value %d (0x%lx) already entered\n",
						root_offset, root_offset);
			else if (IS_A_NUMBER(optarg)) 
				root_offset = stol(optarg, FAULT_ON_ERROR, NULL);
			else if (arg_to_datatype(optarg, sm, RETURN_ON_ERROR) > 1) 
				root_offset = sm->member_offset;
			else
				error(FATAL, "invalid -r argument: %s\n",
					optarg);

			td->flags |= TREE_ROOT_OFFSET_ENTERED; 
			break;

		case 'o':
			if (td->flags & TREE_NODE_OFFSET_ENTERED) 
				error(FATAL,
					"node offset value %d (0x%lx) already entered\n",
						td->node_member_offset, td->node_member_offset);
			else if (IS_A_NUMBER(optarg)) 
				td->node_member_offset = stol(optarg, 
					FAULT_ON_ERROR, NULL);
			else if (arg_to_datatype(optarg, sm, RETURN_ON_ERROR) > 1) 
				td->node_member_offset = sm->member_offset;
			else
				error(FATAL, "invalid -o argument: %s\n",
					optarg);

			td->flags |= TREE_NODE_OFFSET_ENTERED; 
			break;

		case 's':
		case 'S':
			if (td->structname_args++ == 0) 
				hq_open();
			hq_enter((ulong)optarg);
			td->flags |= (c == 's') ? TREE_PARSE_MEMBER : TREE_READ_MEMBER;
			if (count_bits_long(td->flags & (TREE_PARSE_MEMBER|TREE_READ_MEMBER)) > 1)
				error(FATAL, "-S and -s options are mutually exclusive\n");
			break;

		case 'p':
			td->flags |= TREE_POSITION_DISPLAY;
			break;

		case 'N':
			td->flags |= TREE_NODE_POINTER;
			break;

		case 'x':
			if (td->flags & TREE_STRUCT_RADIX_10)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			td->flags |= TREE_STRUCT_RADIX_16;
			break;

		case 'd':
			if (td->flags & TREE_STRUCT_RADIX_16)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			td->flags |= TREE_STRUCT_RADIX_10;
			break;
		case 'v':
			td->flags |= TREE_STRUCT_VERBOSE;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if ((type_flag & (XARRAY_REQUEST|RADIXTREE_REQUEST|MAPLE_REQUEST)) &&
	    (td->flags & TREE_LINEAR_ORDER))
		error(FATAL, "-l option is not applicable to %s\n", type_name);

	if ((type_flag & (XARRAY_REQUEST|RADIXTREE_REQUEST|MAPLE_REQUEST)) &&
	    (td->flags & TREE_NODE_OFFSET_ENTERED))
		error(FATAL, "-o option is not applicable to %s\n", type_name);

	if ((type_flag & (RBTREE_REQUEST|XARRAY_REQUEST|RADIXTREE_REQUEST)) &&
	    (td->flags & TREE_STRUCT_VERBOSE))
		error(FATAL, "-v option is not applicable to %s\n", type_name);

	if ((td->flags & TREE_ROOT_OFFSET_ENTERED) && 
	    (td->flags & TREE_NODE_POINTER))
		error(FATAL, "-r and -N options are mutually exclusive\n");

	if (!args[optind]) {
		error(INFO, "a starting address is required\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if ((sp = symbol_search(args[optind]))) {
		td->start = sp->value;
		goto next_arg;
	}

	if (!IS_A_NUMBER(args[optind])) {	
		if (can_eval(args[optind])) {
			value = eval(args[optind], FAULT_ON_ERROR, NULL);
			if (IS_KVADDR(value)) {
				td->start = value;
				goto next_arg;
			}
		}
		error(FATAL, "invalid start argument: %s\n", args[optind]);
	} 

	if (hexadecimal_only(args[optind], 0)) {
		value = htol(args[optind], FAULT_ON_ERROR, NULL);
		if (IS_KVADDR(value)) {
			td->start = value;
			goto next_arg;
		}
	}
	 
	error(FATAL, "invalid start argument: %s\n", args[optind]);

next_arg:
	if (args[optind+1]) {
		error(INFO, "too many arguments entered\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (td->structname_args) {
		td->structname = (char **)GETBUF(sizeof(char *) *
				td->structname_args);
		retrieve_list((ulong *)td->structname, td->structname_args); 
		hq_close();
	}

	if (!(td->flags & TREE_NODE_POINTER))
		td->start = td->start + root_offset;

	if (CRASHDEBUG(1)) {
		others = 0;
		fprintf(fp, "             flags: %lx (", td->flags);
		if (td->flags & TREE_ROOT_OFFSET_ENTERED)
			fprintf(fp, "%sTREE_ROOT_OFFSET_ENTERED",
				others++ ? "|" : "");
		if (td->flags & TREE_NODE_OFFSET_ENTERED)
			fprintf(fp, "%sTREE_NODE_OFFSET_ENTERED",
				others++ ? "|" : "");
		if (td->flags & TREE_NODE_POINTER)
			fprintf(fp, "%sTREE_NODE_POINTER",
				others++ ? "|" : "");
		if (td->flags & TREE_POSITION_DISPLAY)
			fprintf(fp, "%sTREE_POSITION_DISPLAY",
				others++ ? "|" : "");
		if (td->flags & TREE_STRUCT_RADIX_10)
			fprintf(fp, "%sTREE_STRUCT_RADIX_10",
				others++ ? "|" : "");
		if (td->flags & TREE_STRUCT_RADIX_16)
			fprintf(fp, "%sTREE_STRUCT_RADIX_16",
				others++ ? "|" : "");
		if (td->flags & TREE_PARSE_MEMBER)
			fprintf(fp, "%sTREE_PARSE_MEMBER",
				others++ ? "|" : "");
		if (td->flags & TREE_READ_MEMBER)
			fprintf(fp, "%sTREE_READ_MEMBER",
				others++ ? "|" : "");
		if (td->flags & TREE_LINEAR_ORDER)
			fprintf(fp, "%sTREE_LINEAR_ORDER",
				others++ ? "|" : "");
		if (td->flags & TREE_STRUCT_VERBOSE)
			fprintf(fp, "%sTREE_STRUCT_VERBOSE",
				others++ ? "|" : "");
		fprintf(fp, ")\n");
		fprintf(fp, "              type: ");
			if (type_flag & RADIXTREE_REQUEST)
				fprintf(fp, "radix\n");
			else if (type_flag & XARRAY_REQUEST)
				fprintf(fp, "xarray\n");
			else if (type_flag & MAPLE_REQUEST)
				fprintf(fp, "maple\n");
			else
				fprintf(fp, "red-black%s", 
					type_flag & RBTREE_REQUEST ? 
					"\n" : " (default)\n");
		fprintf(fp, "      node pointer: %s\n",
			td->flags & TREE_NODE_POINTER ? "yes" : "no");
		fprintf(fp, "             start: %lx\n", td->start);
		fprintf(fp, "node_member_offset: %ld\n", td->node_member_offset);
		fprintf(fp, "   structname_args: %d\n", td->structname_args);
		fprintf(fp, "             count: %d\n", td->count);
	}

	td->flags &= ~TREE_NODE_OFFSET_ENTERED;
	td->flags |= VERBOSE;

	hq_open();
	if (type_flag & RADIXTREE_REQUEST)
		do_rdtree(td);
	else if (type_flag & XARRAY_REQUEST)
		do_xatree(td);
	else if (type_flag & MAPLE_REQUEST)
		do_mptree(td);
	else
		do_rbtree(td);
	hq_close();

        if (td->structname_args)
		FREEBUF(td->structname);
}

static ulong RADIX_TREE_MAP_SHIFT = UNINITIALIZED;
static ulong RADIX_TREE_MAP_SIZE = UNINITIALIZED;
static ulong RADIX_TREE_MAP_MASK = UNINITIALIZED;

#define RADIX_TREE_ENTRY_MASK		3UL
#define RADIX_TREE_INTERNAL_NODE	1UL

static void do_radix_tree_iter(ulong node, uint height, char *path,
			       ulong index, struct radix_tree_ops *ops)
{
	uint off;

	if (!hq_enter(node))
		error(FATAL,
			"\nduplicate tree node: %lx\n", node);

	for (off = 0; off < RADIX_TREE_MAP_SIZE; off++) {
		ulong slot;
		ulong shift = (height - 1) * RADIX_TREE_MAP_SHIFT;

		readmem(node + OFFSET(radix_tree_node_slots) +
			sizeof(void *) * off, KVADDR, &slot, sizeof(void *),
			"radix_tree_node.slot[off]", FAULT_ON_ERROR);
		if (!slot)
			continue;

		if (slot & RADIX_TREE_INTERNAL_NODE)
			slot &= ~RADIX_TREE_INTERNAL_NODE;

		if (height == 1)
			ops->entry(node, slot, path, index | off, ops->private);
		else {
			ulong child_index = index | (off << shift);
			char child_path[BUFSIZE];
			sprintf(child_path, "%s/%d", path, off);
			do_radix_tree_iter(slot, height - 1,
					   child_path, child_index, ops);
		}
	}
}

int do_radix_tree_traverse(ulong ptr, int is_root, struct radix_tree_ops *ops)
{
	static ulong max_height = UNINITIALIZED;
	ulong node_p;
	long nlen;
	uint height, is_internal;
	unsigned char shift;
	char path[BUFSIZE];

	if (!VALID_STRUCT(radix_tree_root) || !VALID_STRUCT(radix_tree_node) ||
	    ((!VALID_MEMBER(radix_tree_root_height) ||
	      !VALID_MEMBER(radix_tree_root_rnode) ||
	      !VALID_MEMBER(radix_tree_node_slots) ||
	      !ARRAY_LENGTH(height_to_maxindex)) &&
	     (!VALID_MEMBER(radix_tree_root_rnode) ||
	      !VALID_MEMBER(radix_tree_node_shift) ||
	      !VALID_MEMBER(radix_tree_node_slots) ||
	      !ARRAY_LENGTH(height_to_maxnodes))))
		error(FATAL, "radix trees do not exist or have changed "
			"their format\n");

	if (RADIX_TREE_MAP_SHIFT == UNINITIALIZED) {
		if (!(nlen = MEMBER_SIZE("radix_tree_node", "slots")))
			error(FATAL, "cannot determine length of "
				     "radix_tree_node.slots[] array\n");
		nlen /= sizeof(void *);
		RADIX_TREE_MAP_SHIFT = ffsl(nlen) - 1;
		RADIX_TREE_MAP_SIZE = (1UL << RADIX_TREE_MAP_SHIFT);
		RADIX_TREE_MAP_MASK = (RADIX_TREE_MAP_SIZE-1);

		if (ARRAY_LENGTH(height_to_maxindex))
			max_height = ARRAY_LENGTH(height_to_maxindex);
		else
			max_height = ARRAY_LENGTH(height_to_maxnodes);
	}

	height = 0;
	if (!is_root) {
		node_p = ptr;

		if (node_p & RADIX_TREE_INTERNAL_NODE)
			node_p &= ~RADIX_TREE_INTERNAL_NODE;

		if (VALID_MEMBER(radix_tree_node_height)) {
			readmem(node_p + OFFSET(radix_tree_node_height), KVADDR,
				&height, sizeof(uint), "radix_tree_node height",
				FAULT_ON_ERROR);
		} else if (VALID_MEMBER(radix_tree_node_shift)) {
			readmem(node_p + OFFSET(radix_tree_node_shift), KVADDR,
				&shift, sizeof(shift), "radix_tree_node shift",
				FAULT_ON_ERROR);
			height = (shift / RADIX_TREE_MAP_SHIFT) + 1;
		} else
			error(FATAL, "-N option is not supported or applicable"
				" for radix trees on this architecture or kernel\n");
		if (height > max_height)
			goto error_height;
	} else {
		if (VALID_MEMBER(radix_tree_root_height)) {
			readmem(ptr + OFFSET(radix_tree_root_height), KVADDR, &height,
				sizeof(uint), "radix_tree_root height", FAULT_ON_ERROR);
		}

		readmem(ptr + OFFSET(radix_tree_root_rnode), KVADDR, &node_p,
			sizeof(void *), "radix_tree_root rnode", FAULT_ON_ERROR);
		is_internal = (node_p & RADIX_TREE_INTERNAL_NODE);
		if (node_p & RADIX_TREE_INTERNAL_NODE)
			node_p &= ~RADIX_TREE_INTERNAL_NODE;

		if (is_internal && VALID_MEMBER(radix_tree_node_shift)) {
			readmem(node_p + OFFSET(radix_tree_node_shift), KVADDR, &shift,
				sizeof(shift), "radix_tree_node shift", FAULT_ON_ERROR);
			height = (shift / RADIX_TREE_MAP_SHIFT) + 1;
		}

		if (height > max_height) {
			node_p = ptr;
			goto error_height;
		}
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "radix_tree_node.slots[%ld]\n",
			RADIX_TREE_MAP_SIZE);
		fprintf(fp, "max_height %ld: ", max_height);
		fprintf(fp, "\n");
		fprintf(fp, "pointer at %lx (is_root? %s):\n",
			node_p, is_root ? "yes" : "no");
		if (is_root)
			dump_struct("radix_tree_root", ptr, RADIX(ops->radix));
		else
			dump_struct("radix_tree_node", node_p, RADIX(ops->radix));
	}

	if (height == 0) {
		strcpy(path, "direct");
		ops->entry(node_p, node_p, path, 0, ops->private);
	} else {
		strcpy(path, "root");
		do_radix_tree_iter(node_p, height, path, 0, ops);
	}

	return 0;

error_height:
	fprintf(fp, "radix_tree_node at %lx\n", node_p);
	dump_struct("radix_tree_node", node_p, RADIX(ops->radix));
	error(FATAL, "height %d is greater than "
	      "maximum radix tree height index %ld\n",
	      height, max_height);
	return -1;
}

static ulong XA_CHUNK_SHIFT = UNINITIALIZED;
static ulong XA_CHUNK_SIZE = UNINITIALIZED;
static ulong XA_CHUNK_MASK = UNINITIALIZED;

static void 
do_xarray_iter(ulong node, uint height, char *path,
	       ulong index, struct xarray_ops *ops)
{
	uint off;

	if (!hq_enter(node))
		error(FATAL,
			"\nduplicate tree node: %lx\n", node);

	for (off = 0; off < XA_CHUNK_SIZE; off++) {
		ulong slot;
		ulong shift = (height - 1) * XA_CHUNK_SHIFT;

		readmem(node + OFFSET(xa_node_slots) +
			sizeof(void *) * off, KVADDR, &slot, sizeof(void *),
			"xa_node.slots[off]", FAULT_ON_ERROR);
		if (!slot)
			continue;

		if ((slot & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL)
			slot &= ~XARRAY_TAG_INTERNAL;

		if (height == 1)
			ops->entry(node, slot, path, index | off, ops->private);
		else {
			ulong child_index = index | (off << shift);
			char child_path[BUFSIZE];
			sprintf(child_path, "%s/%d", path, off);
			do_xarray_iter(slot, height - 1,
					   child_path, child_index, ops);
		}
	}
}

int 
do_xarray_traverse(ulong ptr, int is_root, struct xarray_ops *ops)
{
	ulong node_p;
	long nlen;
	uint height, is_internal;
	unsigned char shift;
	char path[BUFSIZE];

	if (!VALID_STRUCT(xarray) || !VALID_STRUCT(xa_node) ||
	      !VALID_MEMBER(xarray_xa_head) ||
	      !VALID_MEMBER(xa_node_slots) ||
	      !VALID_MEMBER(xa_node_shift)) 
		error(FATAL, 
			"xarray facility does not exist or has changed its format\n");

	if (XA_CHUNK_SHIFT == UNINITIALIZED) {
		if ((nlen = MEMBER_SIZE("xa_node", "slots")) <= 0)
			error(FATAL, "cannot determine length of xa_node.slots[] array\n");
		nlen /= sizeof(void *);
		XA_CHUNK_SHIFT = ffsl(nlen) - 1;
		XA_CHUNK_SIZE = (1UL << XA_CHUNK_SHIFT);
		XA_CHUNK_MASK = (XA_CHUNK_SIZE-1);
	}

	height = 0;
	if (!is_root) {
		node_p = ptr;

		if ((node_p & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL)
			node_p &= ~XARRAY_TAG_MASK;

		if (VALID_MEMBER(xa_node_shift)) {
			readmem(node_p + OFFSET(xa_node_shift), KVADDR,
				&shift, sizeof(shift), "xa_node shift",
				FAULT_ON_ERROR);
			height = (shift / XA_CHUNK_SHIFT) + 1;
		} else
			error(FATAL, "-N option is not supported or applicable"
				" for xarrays on this architecture or kernel\n");
	} else {
		readmem(ptr + OFFSET(xarray_xa_head), KVADDR, &node_p,
			sizeof(void *), "xarray xa_head", FAULT_ON_ERROR);
		is_internal = ((node_p & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL);
		if (node_p & XARRAY_TAG_MASK)
			node_p &= ~XARRAY_TAG_MASK;

		if (is_internal && VALID_MEMBER(xa_node_shift)) {
			readmem(node_p + OFFSET(xa_node_shift), KVADDR, &shift,
				sizeof(shift), "xa_node shift", FAULT_ON_ERROR);
			height = (shift / XA_CHUNK_SHIFT) + 1;
		}
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "xa_node.slots[%ld]\n", XA_CHUNK_SIZE);
		fprintf(fp, "pointer at %lx (is_root? %s):\n",
			node_p, is_root ? "yes" : "no");
		if (is_root)
			dump_struct("xarray", ptr, RADIX(ops->radix));
		else
			dump_struct("xa_node", node_p, RADIX(ops->radix));
	}

	if (height == 0) {
		strcpy(path, "direct");
		ops->entry(node_p, node_p, path, 0, ops->private);
	} else {
		strcpy(path, "root");
		do_xarray_iter(node_p, height, path, 0, ops);
	}

	return 0;
}

static void do_rdtree_entry(ulong node, ulong slot, const char *path,
			    ulong index, void *private)
{
	struct tree_data *td = private;
	static struct req_entry **e = NULL;
	uint print_radix;
	int i;

	if (!td->count && td->structname_args) {
		/*
		 * Retrieve all members' info only once (count == 0)
		 * After last iteration all memory will be freed up
		 */
		e = (struct req_entry **)GETBUF(sizeof(*e) * td->structname_args);
		for (i = 0; i < td->structname_args; i++)
			e[i] = fill_member_offsets(td->structname[i]);
	}

	td->count++;

	if (td->flags & VERBOSE)
		fprintf(fp, "%lx\n", slot);

	if (td->flags & TREE_POSITION_DISPLAY) {
		fprintf(fp, "  index: %ld  position: %s/%ld\n", index,
			path, index & RADIX_TREE_MAP_MASK);
	}

	if (td->structname) {
		if (td->flags & TREE_STRUCT_RADIX_10)
			print_radix = 10;
		else if (td->flags & TREE_STRUCT_RADIX_16)
			print_radix = 16;
		else
			print_radix = 0;

		for (i = 0; i < td->structname_args; i++) {
			switch (count_chars(td->structname[i], '.')) {
			case 0:
				dump_struct(td->structname[i], slot, print_radix);
				break;
			default:
				if (td->flags & TREE_PARSE_MEMBER)
					dump_struct_members_for_tree(td, i, slot);
				else if (td->flags & TREE_READ_MEMBER)
					dump_struct_members_fast(e[i], print_radix, slot);
				break;
			}
		}
	}
}

int do_rdtree(struct tree_data *td)
{
	struct radix_tree_ops ops = {
		.entry		= do_rdtree_entry,
		.private	= td,
	};
	int is_root = !(td->flags & TREE_NODE_POINTER);

	if (td->flags & TREE_STRUCT_RADIX_10)
		ops.radix = 10;
	else if (td->flags & TREE_STRUCT_RADIX_16)
		ops.radix = 16;
	else
		ops.radix = 0;

	do_radix_tree_traverse(td->start, is_root, &ops);

	return 0;
}


static void do_xarray_entry(ulong node, ulong slot, const char *path,
			    ulong index, void *private)
{
	struct tree_data *td = private;
	static struct req_entry **e = NULL;
	uint print_radix;
	int i;

	if (!td->count && td->structname_args) {
		/*
		 * Retrieve all members' info only once (count == 0)
		 * After last iteration all memory will be freed up
		 */
		e = (struct req_entry **)GETBUF(sizeof(*e) * td->structname_args);
		for (i = 0; i < td->structname_args; i++)
			e[i] = fill_member_offsets(td->structname[i]);
	}

	td->count++;

	if (td->flags & VERBOSE)
		fprintf(fp, "%lx\n", slot);

	if (td->flags & TREE_POSITION_DISPLAY) {
		fprintf(fp, "  index: %ld  position: %s/%ld\n", index,
			path, index & XA_CHUNK_MASK);
	}

	if (td->structname) {
		if (td->flags & TREE_STRUCT_RADIX_10)
			print_radix = 10;
		else if (td->flags & TREE_STRUCT_RADIX_16)
			print_radix = 16;
		else
			print_radix = 0;

		for (i = 0; i < td->structname_args; i++) {
			switch (count_chars(td->structname[i], '.')) {
			case 0:
				dump_struct(td->structname[i], slot, print_radix);
				break;
			default:
				if (td->flags & TREE_PARSE_MEMBER)
					dump_struct_members_for_tree(td, i, slot);
				else if (td->flags & TREE_READ_MEMBER)
					dump_struct_members_fast(e[i], print_radix, slot);
				break;
			}
		}
	}
}

int do_xatree(struct tree_data *td)
{
	struct xarray_ops ops = {
		.entry		= do_xarray_entry,
		.private	= td,
	};
	int is_root = !(td->flags & TREE_NODE_POINTER);

	if (td->flags & TREE_STRUCT_RADIX_10)
		ops.radix = 10;
	else if (td->flags & TREE_STRUCT_RADIX_16)
		ops.radix = 16;
	else
		ops.radix = 0;

	do_xarray_traverse(td->start, is_root, &ops);

	return 0;
}

int
do_rbtree(struct tree_data *td)
{
	ulong start;
	char pos[BUFSIZE];

	if (!VALID_MEMBER(rb_root_rb_node) || !VALID_MEMBER(rb_node_rb_left) ||
	    !VALID_MEMBER(rb_node_rb_right))
		error(FATAL, "red-black trees do not exist or have changed "
			"their format\n");

	sprintf(pos, "root");

	if (td->flags & TREE_NODE_POINTER)
		start = td->start;
	else
		readmem(td->start + OFFSET(rb_root_rb_node), KVADDR,
			&start, sizeof(void *), "rb_root rb_node", FAULT_ON_ERROR);

	rbtree_iteration(start, td, pos);

	return td->count;
}

void
rbtree_iteration(ulong node_p, struct tree_data *td, char *pos)
{
	int i;
	uint print_radix;
	ulong struct_p, new_p, test_p;
	char new_pos[BUFSIZE];
	static struct req_entry **e;

	if (!node_p)
		return;

	if (!td->count && td->structname_args) {
		/*
		 * Retrieve all members' info only once (count == 0)
		 * After last iteration all memory will be freed up
		 */
		e = (struct req_entry **)GETBUF(sizeof(*e) *
			td->structname_args);
		for (i = 0; i < td->structname_args; i++)
			e[i] = fill_member_offsets(td->structname[i]);
	}

	if (hq_enter(node_p))
		td->count++;
	else
		error(FATAL, "\nduplicate tree entry: %lx\n", node_p);

	if ((td->flags & TREE_LINEAR_ORDER) &&
	    readmem(node_p+OFFSET(rb_node_rb_left), KVADDR, &new_p,
	    sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR) && new_p) {
		if (readmem(new_p+OFFSET(rb_node_rb_left), KVADDR, &test_p,
			sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR|QUIET)) {
			sprintf(new_pos, "%s/l", pos);
			rbtree_iteration(new_p, td, new_pos);
		} else
			error(INFO, "rb_node: %lx: corrupted rb_left pointer: %lx\n",
					node_p, new_p);
	}

	struct_p = node_p - td->node_member_offset;

	if (td->flags & VERBOSE)
		fprintf(fp, "%lx\n", struct_p);
	
	if (td->flags & TREE_POSITION_DISPLAY)
		fprintf(fp, "  position: %s\n", pos);

	if (td->structname) {
		if (td->flags & TREE_STRUCT_RADIX_10)
			print_radix = 10;
		else if (td->flags & TREE_STRUCT_RADIX_16)
			print_radix = 16;
		else
			print_radix = 0;

		for (i = 0; i < td->structname_args; i++) {
			switch(count_chars(td->structname[i], '.'))
			{
			case 0:
				dump_struct(td->structname[i], struct_p, print_radix);
				break;
			default:
				if (td->flags & TREE_PARSE_MEMBER)
					dump_struct_members_for_tree(td, i, struct_p);
				else if (td->flags & TREE_READ_MEMBER)
					dump_struct_members_fast(e[i], print_radix,
						struct_p);
				break;
			}
		}
	}

	if (!(td->flags & TREE_LINEAR_ORDER) &&
	    readmem(node_p+OFFSET(rb_node_rb_left), KVADDR, &new_p,
	    sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR) && new_p) {
		if (readmem(new_p+OFFSET(rb_node_rb_left), KVADDR, &test_p,
			sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR|QUIET)) {
			sprintf(new_pos, "%s/l", pos);
			rbtree_iteration(new_p, td, new_pos);
		} else
			error(INFO, "rb_node: %lx: corrupted rb_left pointer: %lx\n",
					node_p, new_p);
	}

	if (readmem(node_p+OFFSET(rb_node_rb_right), KVADDR, &new_p,
	    sizeof(void *), "rb_node rb_right", RETURN_ON_ERROR) && new_p) {
		if (readmem(new_p+OFFSET(rb_node_rb_left), KVADDR, &test_p,
			sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR|QUIET)) {
			sprintf(new_pos, "%s/r", pos);
			rbtree_iteration(new_p, td, new_pos);
		} else
			error(INFO, "rb_node: %lx: corrupted rb_right pointer: %lx\n",
					node_p, new_p);
	}
}

void
dump_struct_members_for_tree(struct tree_data *td, int idx, ulong struct_p)
{
	int i, argc;
	uint print_radix;
	char *p1;
	char *structname, *members;
	char *arglist[MAXARGS];

	if (td->flags & TREE_STRUCT_RADIX_10)
		print_radix = 10;
	else if (td->flags & TREE_STRUCT_RADIX_16)
		print_radix = 16;
	else
		print_radix = 0;

	structname = GETBUF(strlen(td->structname[idx])+1);
	members = GETBUF(strlen(td->structname[idx])+1);

	strcpy(structname, td->structname[idx]);
	p1 = strstr(structname, ".") + 1;

	strcpy(members, p1);
	replace_string(members, ",", ' ');
	argc = parse_line(members, arglist);

	for (i = 0; i <argc; i++) {
		*p1 = NULLCHAR;
		strcat(structname, arglist[i]);
		dump_struct_member(structname, struct_p, print_radix);
	}

	FREEBUF(structname);
	FREEBUF(members);
}

/*
 *  The next set of functions are a general purpose hashing tool used to
 *  identify duplicate entries in a set of passed-in data, and if found, 
 *  to fail the entry attempt.  When a command wishes to verify a list
 *  of contains unique values, the hash functions should be used in the
 *  following order:
 *
 *      hq_open()
 *      hq_enter(value_1)
 *      hq_enter(value_2)
 *      ...
 *      hq_enter(value_n)
 *      hq_close()
 *
 *  If a duplicate entry is passed in between the hq_open()/hq_close() pair,
 *  hq_enter() will return FALSE;
 */

#define HASH_QUEUE_NONE       (0x1)
#define HASH_QUEUE_FULL       (0x2)
#define HASH_QUEUE_OPEN       (0x4)
#define HASH_QUEUE_CLOSED     (0x8)

#define HQ_ENTRY_CHUNK   (1024)
#define NR_HASH_QUEUES_DEFAULT   (32768UL)
#define HQ_SHIFT         (machdep->pageshift)
#define HQ_INDEX(X)      (((X) >> HQ_SHIFT) % pc->nr_hash_queues)

struct hq_entry {
        int next;
	int order;
        ulong value;
};

struct hq_head {
	int next;
	int qcnt;
};

struct hash_table {
	ulong flags;
	struct hq_head *queue_heads;
	struct hq_entry *memptr;
	long count;
	long index;
	int reallocs;
} hash_table = { 0 };

/*
 *  For starters, allocate a hash table containing HQ_ENTRY_CHUNK entries.
 *  If necessary during runtime, it will be increased in size.
 */
void
hq_init(void)
{
	struct hash_table *ht;

	ht = &hash_table;

	if (pc->nr_hash_queues == 0)
		pc->nr_hash_queues = NR_HASH_QUEUES_DEFAULT;

        if ((ht->queue_heads = (struct hq_head *)malloc(pc->nr_hash_queues *
	    sizeof(struct hq_head))) == NULL) {
		error(INFO, "cannot malloc memory for hash queue heads: %s\n",
			strerror(errno));
		ht->flags = HASH_QUEUE_NONE;
		pc->flags &= ~HASH;
		return;
	}

        if ((ht->memptr = (struct hq_entry *)malloc(HQ_ENTRY_CHUNK * 
	    sizeof(struct hq_entry))) == NULL) {
		error(INFO, "cannot malloc memory for hash queues: %s\n",
			strerror(errno));
		ht->flags = HASH_QUEUE_NONE;
		pc->flags &= ~HASH;
		return;
	}
        
	BZERO(ht->memptr, HQ_ENTRY_CHUNK * sizeof(struct hq_entry));
	ht->count = HQ_ENTRY_CHUNK;
	ht->index = 0;
}

/*
 *  Get a free hash queue entry.  If there's no more available, realloc()
 *  a new chunk of memory with another HQ_ENTRY_CHUNK entries stuck on the end.
 */
static long
alloc_hq_entry(void)
{
	struct hash_table *ht;
	struct hq_entry *new, *end_of_old;

	ht = &hash_table;

	if (++ht->index == ht->count) {
                if (!(new = (void *)realloc((void *)ht->memptr,
		    (ht->count+HQ_ENTRY_CHUNK) * sizeof(struct hq_entry)))) {
			error(INFO, 
			    "cannot realloc memory for hash queues: %s\n",
				strerror(errno));
			ht->flags |= HASH_QUEUE_FULL;
			return(-1);
		}
		ht->reallocs++;
		ht->memptr = new;
		end_of_old = ht->memptr + ht->count;
		BZERO(end_of_old, HQ_ENTRY_CHUNK * sizeof(struct hq_entry));
		ht->count += HQ_ENTRY_CHUNK;
	}

	return(ht->index);
}

/*
 *  Restore the hash queue to its state before the duplicate entry 
 *  was attempted.
 */ 
static void
dealloc_hq_entry(struct hq_entry *entry)
{
        struct hash_table *ht;
        long hqi;

        ht = &hash_table;
	hqi = HQ_INDEX(entry->value);

	ht->index--;

	BZERO(entry, sizeof(struct hq_entry));
	ht->queue_heads[hqi].qcnt--;
}

/*
 *  Initialize the hash table for a hashing session.
 */
int
hq_open(void)
{
	struct hash_table *ht;

	if (!(pc->flags & HASH))
		return FALSE;

	ht = &hash_table;
	if (ht->flags & (HASH_QUEUE_NONE|HASH_QUEUE_OPEN))
		return FALSE;

	ht->flags &= ~(HASH_QUEUE_FULL|HASH_QUEUE_CLOSED);
	BZERO(ht->queue_heads, sizeof(struct hq_head) * pc->nr_hash_queues);
	BZERO(ht->memptr, ht->count * sizeof(struct hq_entry));
	ht->index = 0;

	ht->flags |= HASH_QUEUE_OPEN;

	return TRUE;
}

int
hq_is_open(void)
{
	struct hash_table *ht;

	ht = &hash_table;
	return (ht->flags & HASH_QUEUE_OPEN ? TRUE : FALSE);
}

int
hq_is_inuse(void)
{
	struct hash_table *ht;

	if (!hq_is_open())
		return FALSE;

	ht = &hash_table;
	return (ht->index ? TRUE : FALSE);
}


/*
 *  Close the hash table, returning the number of items hashed in this session.
 */
int
hq_close(void)
{
	struct hash_table *ht;

	ht = &hash_table;

	ht->flags &= ~(HASH_QUEUE_OPEN);
	ht->flags |= HASH_QUEUE_CLOSED;

	if (!(pc->flags & HASH))
		return(0);

	if (ht->flags & HASH_QUEUE_NONE)
		return(0);

	ht->flags &= ~HASH_QUEUE_FULL;

	return(ht->index);
}

char *corrupt_hq = "corrupt hash queue entry: value: %lx next: %d order: %d\n";

/*
 *  For a given value, allocate a hash queue entry and hash it into the 
 *  open hash table.  If a duplicate entry is found, return FALSE; for all 
 *  other possibilities return TRUE.  Note that it's up to the user to deal 
 *  with failure.
 */
int
hq_enter(ulong value)
{
	struct hash_table *ht;
	struct hq_entry *entry;
	struct hq_entry *list_entry;
	long hqi;
	long index;

	if (!(pc->flags & HASH))
		return TRUE;

	ht = &hash_table;

	if (ht->flags & (HASH_QUEUE_NONE|HASH_QUEUE_FULL))
		return TRUE;

	if (!(ht->flags & HASH_QUEUE_OPEN))
		return TRUE;

	if ((index = alloc_hq_entry()) < 0) 
		return TRUE;

	entry = ht->memptr + index;
	if (entry->next || entry->value || entry->order) {
		error(INFO, corrupt_hq,
			entry->value, entry->next, entry->order);
		ht->flags |= HASH_QUEUE_NONE;
		return TRUE;
	}

	entry->next = 0;
	entry->value = value;
	entry->order = index;

	hqi = HQ_INDEX(value);

	if (ht->queue_heads[hqi].next == 0) {
		ht->queue_heads[hqi].next = index;
		ht->queue_heads[hqi].qcnt = 1;
		return TRUE;
	} else
		ht->queue_heads[hqi].qcnt++;

	list_entry = ht->memptr + ht->queue_heads[hqi].next;

	while (TRUE) {
	        if (list_entry->value == entry->value) {
			dealloc_hq_entry(entry);
                	return FALSE;
		}

		if (list_entry->next >= ht->count) {
			error(INFO, corrupt_hq,
			    	list_entry->value, 
				list_entry->next,
				list_entry->order);
			ht->flags |= HASH_QUEUE_NONE;
			return TRUE;
		}

		if (list_entry->next == 0)
			break;

        	list_entry = ht->memptr + list_entry->next;
	}

	list_entry->next = index;

	return TRUE;
}

/*
 *  "hash -d" output
 */
void
dump_hash_table(int verbose)
{
	int i;
	struct hash_table *ht;
	struct hq_entry *list_entry;
	long elements;
	long queues_in_use;
	int others;
	uint minq, maxq; 

	ht = &hash_table;
	others = 0;

	fprintf(fp, "              flags: %lx (", ht->flags);
        if (ht->flags & HASH_QUEUE_NONE)
                fprintf(fp, "%sHASH_QUEUE_NONE", others++ ? "|" : "");
        if (ht->flags & HASH_QUEUE_OPEN)
                fprintf(fp, "%sHASH_QUEUE_OPEN", others++ ? "|" : "");
        if (ht->flags & HASH_QUEUE_CLOSED)
                fprintf(fp, "%sHASH_QUEUE_CLOSED", others++ ? "|" : "");
        if (ht->flags & HASH_QUEUE_FULL)
                fprintf(fp, "%sHASH_QUEUE_FULL", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "  queue_heads[%ld]: %lx\n", pc->nr_hash_queues, 
		(ulong)ht->queue_heads);
	fprintf(fp, "             memptr: %lx\n", (ulong)ht->memptr);
	fprintf(fp, "              count: %ld  ", ht->count);
	if (ht->reallocs)
		fprintf(fp, "  (%d reallocs)", ht->reallocs);
	fprintf(fp, "\n");
	fprintf(fp, "              index: %ld\n", ht->index);

	queues_in_use = 0;
	minq = ~(0);
	maxq = 0;

	for (i = 0; i < pc->nr_hash_queues; i++) {
               	if (ht->queue_heads[i].next == 0) {
			minq = 0;
                       	continue;
		}

		if (ht->queue_heads[i].qcnt < minq)
			minq = ht->queue_heads[i].qcnt;
		if (ht->queue_heads[i].qcnt > maxq)
			maxq = ht->queue_heads[i].qcnt;

               	queues_in_use++;
	}

	elements = 0;
	list_entry = ht->memptr;
        for (i = 0; i < ht->count; i++, list_entry++) {
	         if (!list_entry->order) {
	                if (list_entry->value || list_entry->next)
				goto corrupt_list_entry;
	                continue;
	         }
	
	         if (list_entry->next >= ht->count)
	                        goto corrupt_list_entry;

	         ++elements;
       	}

	if (elements != ht->index)
        	fprintf(fp, "     elements found: %ld (expected %ld)\n", 
			elements, ht->index);
        fprintf(fp, "      queues in use: %ld of %ld\n", queues_in_use, 
		pc->nr_hash_queues);
	fprintf(fp, " queue length range: %d to %d\n", minq, maxq);

	if (verbose) {
		if (!elements) {
        		fprintf(fp, "            entries: (none)\n");
			return;
		}

        	fprintf(fp, "            entries: ");

        	list_entry = ht->memptr;
	        for (i = 0; i < ht->count; i++, list_entry++) {
	                 if (list_entry->order)
	                        fprintf(fp, "%s%lx (%d)\n", 
					list_entry->order == 1 ?
					"" : "                     ",
	                                list_entry->value, list_entry->order);
	        }
	}
	return;

corrupt_list_entry:

        error(INFO, corrupt_hq,
        	list_entry->value, list_entry->next, list_entry->order);
        ht->flags |= HASH_QUEUE_NONE;
}

/*
 *  Retrieve the count of, and optionally stuff a pre-allocated array with,
 *  the current hash table entries.  The entries will be sorted according
 *  to the order in which they were entered, so from this point on, no
 *  further hq_enter() operations on this list will be allowed.  However, 
 *  multiple calls to retrieve_list are allowed because the second and 
 *  subsequent ones will go directly to where the non-zero (valid) entries 
 *  start in the potentially very large list_entry memory chunk.
 */
int
retrieve_list(ulong array[], int count)
{
        int i; 
        struct hash_table *ht;
        struct hq_entry *list_entry;
        int elements;

	if (!(pc->flags & HASH))
		error(FATAL, 
		    "cannot perform this command with hash turned off\n");

        ht = &hash_table;

	list_entry = ht->memptr;
	for (i = elements = 0; i < ht->count; i++, list_entry++) {
		if (!list_entry->order) {
			if (list_entry->value || list_entry->next)
				goto corrupt_list_entry;
			continue;
		}

                if (list_entry->next >= ht->count) 
			goto corrupt_list_entry;

		if (array) 
			array[elements] = list_entry->value; 

                if (++elements == count)
                       	break;
	}

	return elements;

corrupt_list_entry:

        error(INFO, corrupt_hq,
               list_entry->value, list_entry->next, list_entry->order);
        ht->flags |= HASH_QUEUE_NONE;
        return(-1);
}

/*
 *  For a given value, check to see if a hash queue entry exists.  If an
 *  entry is found, return TRUE; for all other possibilities return FALSE.
 */
int
hq_entry_exists(ulong value)
{
	struct hash_table *ht;
	struct hq_entry *list_entry;
	long hqi;

	if (!(pc->flags & HASH))
		return FALSE;

	ht = &hash_table;

	if (ht->flags & (HASH_QUEUE_NONE))
		return FALSE;

	if (!(ht->flags & HASH_QUEUE_OPEN))
		return FALSE;

	hqi = HQ_INDEX(value);
	list_entry = ht->memptr + ht->queue_heads[hqi].next;

	while (TRUE) {
		if (list_entry->value == value)
			return TRUE;

		if (list_entry->next >= ht->count) {
			error(INFO, corrupt_hq,
				list_entry->value, 
				list_entry->next,
 				list_entry->order);
			ht->flags |= HASH_QUEUE_NONE;
			return FALSE;
		}

		if (list_entry->next == 0)
			break;

		list_entry = ht->memptr + list_entry->next;
	}

	return FALSE;
}

/*
 *  K&R power function for integers
 */
long
power(long base, int exp)
{
	int i;
	long p;

	p = 1;
	for (i = 1; i <= exp; i++)
		p = p * base;

	return p;
}

long long 
ll_power(long long base, long long exp)
{
        long long i;
        long long p;

        p = 1;
        for (i = 1; i <= exp; i++)
                p = p * base;

        return p;
}

/*
 *  Internal buffer allocation scheme to avoid inline malloc() calls and 
 *  resultant memory leaks due to aborted commands.  These buffers are
 *  for TEMPORARY use on a per-command basis.  They are allocated by calls
 *  to GETBUF(size).  They can explicitly freed by FREEBUF(address), but
 *  they are all freed by free_all_bufs() which is called in a number of
 *  places, most not
 */

#define NUMBER_1K_BUFS  (10)
#define NUMBER_2K_BUFS  (10)
#define NUMBER_4K_BUFS   (5)
#define NUMBER_8K_BUFS   (5)
#define NUMBER_32K_BUFS  (1)

#define SHARED_1K_BUF_FULL   (0x003ff)
#define SHARED_2K_BUF_FULL   (0x003ff)
#define SHARED_4K_BUF_FULL   (0x0001f)
#define SHARED_8K_BUF_FULL   (0x0001f)
#define SHARED_32K_BUF_FULL  (0x00001)

#define SHARED_1K_BUF_AVAIL(X) \
  (NUMBER_1K_BUFS && !(((X) & SHARED_1K_BUF_FULL) == SHARED_1K_BUF_FULL))
#define SHARED_2K_BUF_AVAIL(X) \
  (NUMBER_2K_BUFS && !(((X) & SHARED_2K_BUF_FULL) == SHARED_2K_BUF_FULL))
#define SHARED_4K_BUF_AVAIL(X) \
  (NUMBER_4K_BUFS && !(((X) & SHARED_4K_BUF_FULL) == SHARED_4K_BUF_FULL))
#define SHARED_8K_BUF_AVAIL(X) \
  (NUMBER_8K_BUFS && !(((X) & SHARED_8K_BUF_FULL) == SHARED_8K_BUF_FULL))
#define SHARED_32K_BUF_AVAIL(X) \
  (NUMBER_32K_BUFS && !(((X) & SHARED_32K_BUF_FULL) == SHARED_32K_BUF_FULL))

#define B1K  (0)
#define B2K  (1)
#define B4K  (2)
#define B8K  (3)
#define B32K (4)

#define SHARED_BUF_SIZES  (B32K+1)
#define MAX_MALLOC_BUFS   (2000)
#define MAX_CACHE_SIZE    (KILOBYTES(32))

struct shared_bufs {
	char buf_1K[NUMBER_1K_BUFS][1024];
	char buf_2K[NUMBER_2K_BUFS][2048];
	char buf_4K[NUMBER_4K_BUFS][4096];
	char buf_8K[NUMBER_8K_BUFS][8192];
	char buf_32K[NUMBER_32K_BUFS][32768];
	long buf_1K_used;
	long buf_2K_used;
	long buf_4K_used;
	long buf_8K_used;
	long buf_32K_used;
        long buf_1K_maxuse;
        long buf_2K_maxuse;
        long buf_4K_maxuse;
        long buf_8K_maxuse;
        long buf_32K_maxuse;
        long buf_1K_ovf;
        long buf_2K_ovf;
        long buf_4K_ovf;
        long buf_8K_ovf;
        long buf_32K_ovf;
	int buf_inuse[SHARED_BUF_SIZES];
	char *malloc_bp[MAX_MALLOC_BUFS];
	long smallest;
	long largest;
	long embedded;
	long max_embedded;
	long mallocs;
	long frees;
	double total;
	ulong reqs;
} shared_bufs;

void
buf_init(void)
{
	struct shared_bufs *bp;

	bp = &shared_bufs;
	BZERO(bp, sizeof(struct shared_bufs));

	bp->smallest = 0x7fffffff; 
	bp->total = 0.0;

#ifdef VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_1K, sizeof(bp->buf_1K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_2K, sizeof(bp->buf_2K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_4K, sizeof(bp->buf_4K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_8K, sizeof(bp->buf_8K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_32K, sizeof(bp->buf_32K));

	VALGRIND_CREATE_MEMPOOL(&bp->buf_1K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_2K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_4K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_8K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_32K, 0, 1);
#endif
}

/*
 *  Free up all buffers used by the last command.
 */
void free_all_bufs(void)
{
	int i;
	struct shared_bufs *bp;

	bp = &shared_bufs;
	bp->embedded = 0;

        for (i = 0; i < SHARED_BUF_SIZES; i++)
                bp->buf_inuse[i] = 0;

	for (i = 0; i < MAX_MALLOC_BUFS; i++) {
		if (bp->malloc_bp[i]) {
			free(bp->malloc_bp[i]);
			bp->malloc_bp[i] = NULL;
			bp->frees++;
		}
	}

	if (bp->mallocs != bp->frees)
		error(WARNING, "malloc/free mismatch (%ld/%ld)\n",
			bp->mallocs, bp->frees);

#ifdef VALGRIND
	VALGRIND_DESTROY_MEMPOOL(&bp->buf_1K);
	VALGRIND_DESTROY_MEMPOOL(&bp->buf_2K);
	VALGRIND_DESTROY_MEMPOOL(&bp->buf_4K);
	VALGRIND_DESTROY_MEMPOOL(&bp->buf_8K);
	VALGRIND_DESTROY_MEMPOOL(&bp->buf_32K);

	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_1K, sizeof(bp->buf_1K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_2K, sizeof(bp->buf_2K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_4K, sizeof(bp->buf_4K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_8K, sizeof(bp->buf_8K));
	VALGRIND_MAKE_MEM_NOACCESS(&bp->buf_32K, sizeof(bp->buf_32K));

	VALGRIND_CREATE_MEMPOOL(&bp->buf_1K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_2K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_4K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_8K, 0, 1);
	VALGRIND_CREATE_MEMPOOL(&bp->buf_32K, 0, 1);
#endif
}

/*
 *  Free a specific buffer that may have been returned by malloc().
 *  If the address is one of the static buffers, look for it and
 *  clear its inuse bit.
 */
void 
freebuf(char *addr)
{
        int i;
        struct shared_bufs *bp;

        bp = &shared_bufs;
	bp->embedded--;

        if (CRASHDEBUG(8)) {
		INDENT(bp->embedded*2);
                fprintf(fp, "FREEBUF(%ld)\n", bp->embedded);
        }

	for (i = 0; i < NUMBER_1K_BUFS; i++) {
		if (addr == (char *)&bp->buf_1K[i]) {
			bp->buf_inuse[B1K] &= ~(1 << i);
#ifdef VALGRIND
			VALGRIND_MEMPOOL_FREE(&bp->buf_1K, addr);
#endif
			return;
		}
	}

	for (i = 0; i < NUMBER_2K_BUFS; i++) {
		if (addr == (char *)&bp->buf_2K[i]) {
			bp->buf_inuse[B2K] &= ~(1 << i);
#ifdef VALGRIND
			VALGRIND_MEMPOOL_FREE(&bp->buf_2K, addr);
#endif
			return;
		}
	}

	for (i = 0; i < NUMBER_4K_BUFS; i++) {
		if (addr == (char *)&bp->buf_4K[i]) {
			bp->buf_inuse[B4K] &= ~(1 << i);
#ifdef VALGRIND
			VALGRIND_MEMPOOL_FREE(&bp->buf_4K, addr);
#endif
			return;
		}
	}

	for (i = 0; i < NUMBER_8K_BUFS; i++) {
		if (addr == (char *)&bp->buf_8K[i]) {
			bp->buf_inuse[B8K] &= ~(1 << i);
#ifdef VALGRIND
			VALGRIND_MEMPOOL_FREE(&bp->buf_8K, addr);
#endif
			return;
		}
	}

        for (i = 0; i < NUMBER_32K_BUFS; i++) {
                if (addr == (char *)&bp->buf_32K[i]) {
                        bp->buf_inuse[B32K] &= ~(1 << i);
#ifdef VALGRIND
			VALGRIND_MEMPOOL_FREE(&bp->buf_32K, addr);
#endif
                        return;
                }
        }

        for (i = 0; i < MAX_MALLOC_BUFS; i++) {
                if (bp->malloc_bp[i] == addr) {
                        free(bp->malloc_bp[i]);
                        bp->malloc_bp[i] = NULL;
                        bp->frees++;
                        return;
                }
        }

	error(FATAL, 
	    "freeing an unknown buffer -- shared buffer inconsistency!\n");
}

/* DEBUG */
void
dump_embedded(char *s)
{
        struct shared_bufs *bp;
	char *p1;

	p1 = s ? s : "";

        bp = &shared_bufs;
        console("%s: embedded: %ld  mallocs: %ld  frees: %ld\n", 
		p1, bp->embedded, bp->mallocs, bp->frees);
}
/* DEBUG */
long
get_embedded(void)
{
	struct shared_bufs *bp;

        bp = &shared_bufs;
	return(bp->embedded);
}

/*
 *  "help -b" output
 */
void
dump_shared_bufs(void)
{
        int i;
        struct shared_bufs *bp;

        bp = &shared_bufs;

        fprintf(fp, "   buf_1K_used: %ld\n", bp->buf_1K_used);
        fprintf(fp, "   buf_2K_used: %ld\n", bp->buf_2K_used);
        fprintf(fp, "   buf_4K_used: %ld\n", bp->buf_4K_used);
        fprintf(fp, "   buf_8K_used: %ld\n", bp->buf_8K_used);
        fprintf(fp, "  buf_32K_used: %ld\n", bp->buf_32K_used);

        fprintf(fp, "    buf_1K_ovf: %ld\n", bp->buf_1K_ovf);
        fprintf(fp, "    buf_2K_ovf: %ld\n", bp->buf_2K_ovf);
        fprintf(fp, "    buf_4K_ovf: %ld\n", bp->buf_4K_ovf);
        fprintf(fp, "    buf_8K_ovf: %ld\n", bp->buf_8K_ovf);
        fprintf(fp, "   buf_32K_ovf: %ld\n", bp->buf_32K_ovf);

        fprintf(fp, " buf_1K_maxuse: %2ld of %d\n", bp->buf_1K_maxuse, 
		NUMBER_1K_BUFS);
        fprintf(fp, " buf_2K_maxuse: %2ld of %d\n", bp->buf_2K_maxuse, 
		NUMBER_2K_BUFS);
        fprintf(fp, " buf_4K_maxuse: %2ld of %d\n", bp->buf_4K_maxuse, 
		NUMBER_4K_BUFS);
        fprintf(fp, " buf_8K_maxuse: %2ld of %d\n", bp->buf_8K_maxuse, 
		NUMBER_8K_BUFS);
        fprintf(fp, "buf_32K_maxuse: %2ld of %d\n", bp->buf_32K_maxuse, 
		NUMBER_32K_BUFS);

	fprintf(fp, "  buf_inuse[%d]: ", SHARED_BUF_SIZES);
	for (i = 0; i < SHARED_BUF_SIZES; i++)
		fprintf(fp, "[%lx]", (ulong)bp->buf_inuse[i]);
	fprintf(fp, "\n");

        for (i = 0; i < MAX_MALLOC_BUFS; i++) 
		if (bp->malloc_bp[i])
			fprintf(fp, "  malloc_bp[%d]: %lx\n", 
				i, (ulong)bp->malloc_bp[i]);

	if (bp->smallest == 0x7fffffff)
        	fprintf(fp, "      smallest: 0\n");
	else 
        	fprintf(fp, "      smallest: %ld\n", bp->smallest);
        fprintf(fp, "       largest: %ld\n", bp->largest);

	fprintf(fp, "      embedded: %ld\n", bp->embedded);
	fprintf(fp, "  max_embedded: %ld\n", bp->max_embedded);
	fprintf(fp, "       mallocs: %ld\n", bp->mallocs);
	fprintf(fp, "         frees: %ld\n", bp->frees);
	fprintf(fp, "    reqs/total: %ld/%.0f\n", bp->reqs, bp->total);
	fprintf(fp, "  average size: %.0f\n", bp->total/bp->reqs);
}

/*
 *  Try to get one of the static buffers first.  If not available, fall
 *  through and get it from malloc(), keeping trace of the returned address.
 */

#define SHARED_BUFSIZE(size) \
                ((size <= 1024) ? 1024 >> 7 : \
                    ((size <= 2048) ? 2048 >> 7 : \
                        ((size <= 4096) ? 4096 >> 7 : \
                            ((size <= 8192) ? 8192 >> 7 : \
                                ((size <= 32768) ? 32768 >> 7 : -1)))))

char *
getbuf(long reqsize)
{
	int i;
	int index;
	int bdx;
	int mask;
	struct shared_bufs *bp;
	char *bufp;

	if (!reqsize) { 
                ulong retaddr = (ulong)__builtin_return_address(0);
                error(FATAL, "zero-size memory allocation! (called from %lx)\n",
                        retaddr);
        }

	bp = &shared_bufs;

	index = SHARED_BUFSIZE(reqsize);

	if (CRASHDEBUG(7) && (reqsize > MAX_CACHE_SIZE))
		error(NOTE, "GETBUF request > MAX_CACHE_SIZE: %ld\n", 
			reqsize);

	if (CRASHDEBUG(8)) {
		INDENT(bp->embedded*2);
		fprintf(fp, "GETBUF(%ld -> %ld)\n", reqsize, bp->embedded);
	}

	bp->embedded++;
	if (bp->embedded > bp->max_embedded)
		bp->max_embedded = bp->embedded;

	if (reqsize < bp->smallest)
		bp->smallest = reqsize;
	if (reqsize > bp->largest)
		bp->largest = reqsize;

	bp->total += reqsize;
	bp->reqs++;

	switch (index)
	{
	case -1:
		break;

	case 8:
                if (SHARED_1K_BUF_AVAIL(bp->buf_inuse[B1K])) {
                        mask = ~(bp->buf_inuse[B1K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_1K[bdx];
                        bp->buf_1K_used++;
                        bp->buf_inuse[B1K] |= (1 << bdx);
			bp->buf_1K_maxuse = MAX(bp->buf_1K_maxuse, 
				count_bits_int(bp->buf_inuse[B1K]));
#ifdef VALGRIND
			VALGRIND_MEMPOOL_ALLOC(&bp->buf_1K, bufp, 1024);
#endif
                        BZERO(bufp, 1024);
                        return(bufp);
                }
		bp->buf_1K_ovf++;  /* FALLTHROUGH */

	case 16:
                if (SHARED_2K_BUF_AVAIL(bp->buf_inuse[B2K])) {
                        mask = ~(bp->buf_inuse[B2K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_2K[bdx];
                        bp->buf_2K_used++;
                        bp->buf_inuse[B2K] |= (1 << bdx);
                        bp->buf_2K_maxuse = MAX(bp->buf_2K_maxuse,
                                count_bits_int(bp->buf_inuse[B2K]));
#ifdef VALGRIND
			VALGRIND_MEMPOOL_ALLOC(&bp->buf_2K, bufp, 2048);
#endif
                        BZERO(bufp, 2048);
                        return(bufp);
                }
		bp->buf_2K_ovf++;  /* FALLTHROUGH */

	case 32:
                if (SHARED_4K_BUF_AVAIL(bp->buf_inuse[B4K])) {
                        mask = ~(bp->buf_inuse[B4K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_4K[bdx];
                        bp->buf_4K_used++;
                        bp->buf_inuse[B4K] |= (1 << bdx);
                        bp->buf_4K_maxuse = MAX(bp->buf_4K_maxuse,
                                count_bits_int(bp->buf_inuse[B4K]));
#ifdef VALGRIND
			VALGRIND_MEMPOOL_ALLOC(&bp->buf_4K, bufp, 4096);
#endif
                        BZERO(bufp, 4096);
                        return(bufp);
                }
		bp->buf_4K_ovf++;  /* FALLTHROUGH */

        case 64:
                if (SHARED_8K_BUF_AVAIL(bp->buf_inuse[B8K])) {
                        mask = ~(bp->buf_inuse[B8K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_8K[bdx];
                        bp->buf_8K_used++;
                        bp->buf_inuse[B8K] |= (1 << bdx);
                        bp->buf_8K_maxuse = MAX(bp->buf_8K_maxuse,
                                count_bits_int(bp->buf_inuse[B8K]));
#ifdef VALGRIND
			VALGRIND_MEMPOOL_ALLOC(&bp->buf_8K, bufp, 8192);
#endif
                        BZERO(bufp, 8192);
                        return(bufp);
                }
		bp->buf_8K_ovf++;  /* FALLTHROUGH */

	case 256:
               if (SHARED_32K_BUF_AVAIL(bp->buf_inuse[B32K])) {
                        mask = ~(bp->buf_inuse[B32K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_32K[bdx];
                        bp->buf_32K_used++;
                        bp->buf_inuse[B32K] |= (1 << bdx);
                        bp->buf_32K_maxuse = MAX(bp->buf_32K_maxuse,
                                count_bits_int(bp->buf_inuse[B32K]));
#ifdef VALGRIND
			VALGRIND_MEMPOOL_ALLOC(&bp->buf_32K, bufp, 32768);
#endif
                        BZERO(bufp, 32768);
                        return(bufp);
                }
                bp->buf_32K_ovf++;
		break;
	}

	for (i = 0; i < MAX_MALLOC_BUFS; i++) {
		if (bp->malloc_bp[i])
			continue;

		if ((bp->malloc_bp[i] = (char *)calloc(reqsize, 1))) {
			bp->mallocs++;
			return(bp->malloc_bp[i]);
		}

		break;
	}

	dump_shared_bufs();
	
	return ((char *)(long)
		error(FATAL, "cannot allocate any more memory!\n"));
}

/*
 *  Change the size of the previously-allocated memory block 
 *  pointed to by oldbuf to newsize bytes.  Copy the minimum
 *  of oldsize and newsize bytes from the oldbuf to the newbuf,
 *  and return the address of the new buffer, which will have
 *  a different address than oldbuf.
 */
char *
resizebuf(char *oldbuf, long oldsize, long newsize)
{
	char *newbuf;

	newbuf = GETBUF(newsize);
	BCOPY(oldbuf, newbuf, MIN(oldsize, newsize));
	FREEBUF(oldbuf);

	return newbuf;
}

/*
 *  Duplicate a string into a buffer allocated with GETBUF().
 */
char *
strdupbuf(char *oldstring)
{
	char *newstring;

	newstring = GETBUF(strlen(oldstring)+1);
	strcpy(newstring, oldstring);
	return newstring;
}

/*
 *  Return the number of bits set in an int or long.
 */

int
count_bits_int(int val)
{
	int i, cnt;
	int total;

	cnt = sizeof(int) * 8;

	for (i = total = 0; i < cnt; i++) {
		if (val & 1)
			total++;
		val >>= 1;
	}

	return total;
}

int
count_bits_long(ulong val)
{
        int i, cnt;
        int total;

        cnt = sizeof(long) * 8;

        for (i = total = 0; i < cnt; i++) {
                if (val & 1)
                        total++;
                val >>= 1;
        }

        return total;
}

int
highest_bit_long(ulong val)
{
        int i, cnt;
        int total;
	int highest;

	highest = -1;
        cnt = sizeof(long) * 8;

        for (i = total = 0; i < cnt; i++) {
                if (val & 1)
                        highest = i;
                val >>= 1;
        }

        return highest;
}

int
lowest_bit_long(ulong val)
{
        int i, cnt;
	int lowest;

	lowest = -1;
	cnt = sizeof(long) * 8;

        for (i = 0; i < cnt; i++) {
                if (val & 1) {
                        lowest = i;
			break;
		}
                val >>= 1;
        }

	return lowest;
}

/*
 *  Debug routine to stop whatever's going on in its tracks.
 */
void
drop_core(char *s)
{
	volatile int *nullptr;
	int i ATTRIBUTE_UNUSED;

	if (s && ascii_string(s))
		fprintf(stderr, "%s", s);

	kill((pid_t)pc->program_pid, 3);

	nullptr = NULL;
	while (TRUE)
		i = *nullptr;
}


/*
 *  For debug output to a device other than the current terminal.
 *  pc->console must have been preset by:
 *
 *   1. by an .rc file setting:    "set console /dev/whatever"
 *   2. by a runtime command:      "set console /dev/whatever"
 *   3. during program invocation:  "-c /dev/whatever"
 *
 *  The first time it's called, the device will be opened.
 */
int
console(const char *fmt, ...)
{
        char output[BUFSIZE*2];
	va_list ap;

        if (!pc->console || !strlen(pc->console) || 
            (pc->flags & NO_CONSOLE) || (pc->confd == -1))
                return 0;

        if (!fmt || !strlen(fmt))
                return 0;

        va_start(ap, fmt);
        (void)vsnprintf(output, BUFSIZE*2, fmt, ap);
        va_end(ap);

        if (pc->confd == -2) {
                if ((pc->confd = open(pc->console, O_WRONLY|O_NDELAY)) < 0) {
                        error(INFO, "console device %s: %s\n",
                                pc->console, strerror(errno), 0, 0);
                        return 0;
                }
        }

        return(write(pc->confd, output, strlen(output)));
}

/*
 *  Allocate space to store the designated console device name.
 *  If a console device pre-exists, free its name space and close the device.
 */
void
create_console_device(char *dev)
{
        if (pc->console) {
                if (pc->confd != -1)
                        close(pc->confd);
                free(pc->console);
        }

        pc->confd = -2;

        if ((pc->console = (char *)malloc(strlen(dev)+1)) == NULL)
                fprintf(stderr, "console name malloc: %s\n", strerror(errno));
        else {
                strcpy(pc->console, dev);
                if (console("debug console [%ld]: %s\n", 
		    pc->program_pid, (ulong)pc->console) < 0) {
			close(pc->confd);
                	free(pc->console);
			pc->console = NULL;
			pc->confd = -1;
			if (!(pc->flags & RUNTIME))
				error(INFO, "cannot set console to %s\n", dev);
				
		}
        }
}

/*
 *  Disable console output without closing the device.  
 *  Typically used with CONSOLE_OFF() macro.
 */
int
console_off(void)
{
        int orig_no_console;

        orig_no_console = pc->flags & NO_CONSOLE;
        pc->flags |= NO_CONSOLE;

        return orig_no_console;
}

/*
 *  Re-enable console output.  Typically used with CONSOLE_ON() macro.
 */
int
console_on(int orig_no_console)
{
        if (!orig_no_console)
                pc->flags &= ~NO_CONSOLE;

        return(pc->flags & NO_CONSOLE);
}

/*
 *  Print a string to the console device with no formatting, useful for
 *  sending strings containing % signs.
 */
int
console_verbatim(char *s)
{
        char *p;
	int cnt;

        if (!pc->console || !strlen(pc->console) || 
	    (pc->flags & NO_CONSOLE) || (pc->confd == -1))
                return 0;

        if (!s || !strlen(s))
                return 0;

        if (pc->confd == -2) {
                if ((pc->confd = open(pc->console, O_WRONLY|O_NDELAY)) < 0) {
                        fprintf(stderr, "%s: %s\n",
                                pc->console, strerror(errno));
                        return 0;
                }
        }

        for (cnt = 0, p = s; *p; p++) {
                if (write(pc->confd, p, 1) != 1) 
			break;
		cnt++;
        }

	return cnt;
}

/*
 *  Set up a signal handler.
 */
void
sigsetup(int sig, void *handler, struct sigaction *act,struct sigaction *oldact)
{
	BZERO(act, sizeof(struct sigaction));
        act->sa_handler = handler;
        act->sa_flags = SA_NOMASK;
        sigaction(sig, act, oldact);
}

/*
 *  Convert a jiffies-based time value into a string showing the
 *  the number of days, hours:minutes:seconds.
 */
#define SEC_MINUTES  (60)
#define SEC_HOURS    (60 * SEC_MINUTES)
#define SEC_DAYS     (24 * SEC_HOURS)

char *
convert_time(ulonglong count, char *buf)
{
	ulonglong total, days, hours, minutes, seconds;

	if (CRASHDEBUG(2))
		error(INFO, "convert_time: %lld (%llx)\n", count, count);

	if (!machdep->hz) {
		sprintf(buf, "(cannot calculate: unknown HZ value)");
		return buf;
	}

        total = (count)/(ulonglong)machdep->hz;

        days = total / SEC_DAYS;
        total %= SEC_DAYS;
        hours = total / SEC_HOURS;
        total %= SEC_HOURS;
        minutes = total / SEC_MINUTES;
        seconds = total % SEC_MINUTES;

	buf[0] = NULLCHAR;

        if (days)
        	sprintf(buf, "%llu days, ", days);
        sprintf(&buf[strlen(buf)], "%02llu:%02llu:%02llu", 
		hours, minutes, seconds);

	return buf;
}

/*
 * Convert a calendar time into a null-terminated string like ctime(), but
 * the result string contains the time zone string and does not ends with a
 * linefeed ('\n').  If localtime() or strftime() fails, fails back to return
 * POSIX time (seconds since the Epoch) or ctime() string respectively.
 *
 * NOTE: The return value points to a statically allocated string which is
 * overwritten by subsequent calls.
 */
char *
ctime_tz(time_t *timep)
{
	static char buf[64];
	struct tm *tm;
	size_t size;

	if (!timep)
		return NULL;

	tm = localtime(timep);
	if (!tm) {
		snprintf(buf, sizeof(buf), "%ld", *timep);
		return buf;
	}

	size = strftime(buf, sizeof(buf), "%a %b %e %T %Z %Y", tm);
	if (!size)
		return strip_linefeeds(ctime(timep));

	return buf;
}

/*
 *  Stall for a number of microseconds.
 */
void
stall(ulong microseconds)
{
        struct timeval delay;

        delay.tv_sec = 0;
        delay.tv_usec = (__time_t)microseconds;

        (void) select(0, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &delay);
}


/*
 *  Fill a buffer with a page count translated to a GB/MB/KB value.
 */ 
char *
pages_to_size(ulong pages, char *buf)
{
	double total;
	char *p;

	if (pages == 0) {
		sprintf(buf, "0");
		return buf;
	}

	total = (double)pages * (double)PAGESIZE();

    	if (total >= GIGABYTES(1))
        	sprintf(buf, "%.1f GB", total/(double)GIGABYTES(1));
    	else if (total >= MEGABYTES(1))
        	sprintf(buf, "%.1f MB", total/(double)MEGABYTES(1));
        else
        	sprintf(buf, "%ld KB", (ulong)(total/(double)KILOBYTES(1)));

	if ((p = strstr(buf, ".0 ")))
		memmove(p, p + 2, sizeof(" GB"));

	return buf;
}

/*
 *  If the list_head.next value points to itself, it's an emtpy list.
 */
int
empty_list(ulong list_head_addr)
{
	ulong next;
 
	if (!readmem(list_head_addr, KVADDR, &next, sizeof(void *),
            "list_head next contents", RETURN_ON_ERROR))
		return TRUE;

	return (next == list_head_addr);
}

int
machine_type(char *type)
{
	return STREQ(MACHINE_TYPE, type);
}

int 
machine_type_mismatch(char *file, char *e_machine, char *alt, ulong query)
{
	if (machine_type(e_machine) || machine_type(alt))
		return FALSE;

	if (query == KDUMP_LOCAL)  /* already printed by NETDUMP_LOCAL */
		return TRUE;

	error(WARNING, "machine type mismatch:\n");

	fprintf(fp, "         crash utility: %s\n", MACHINE_TYPE);
	fprintf(fp, "         %s: %s%s%s\n\n", file, e_machine,
		alt ? " or " : "", alt ? alt : "");
		
	return TRUE;
}
void
command_not_supported()
{
	error(FATAL, 
	    "command not supported or applicable on this architecture or kernel\n");
}

void
option_not_supported(int c)
{
	error(FATAL, 
	    "-%c option not supported or applicable on this architecture or kernel\n", 
		(char)c);
}

static int please_wait_len = 0;

void
please_wait(char *s)
{
	int fd;
	char buf[BUFSIZE];

	if ((pc->flags & SILENT) || !DUMPFILE() || (pc->flags & RUNTIME))
		return;

	if (!(pc->flags & TTY) && KVMDUMP_DUMPFILE()) {
		if (!isatty(fileno(stdin)) ||
		    ((fd = open("/dev/tty", O_RDONLY)) < 0))
			return;
		close(fd);
	}

	pc->flags |= PLEASE_WAIT;

        please_wait_len = sprintf(buf, "\rplease wait... (%s)", s);
	fprintf(fp, "%s", buf);
        fflush(fp);
}

void
please_wait_done(void)
{
	if (!(pc->flags & PLEASE_WAIT))
		return;

	pc->flags &= ~PLEASE_WAIT;

	fprintf(fp, "\r");
	pad_line(fp, please_wait_len, ' ');
	fprintf(fp, "\r");
	fflush(fp);
}

/*
 *  Compare two pathnames.
 */
int
pathcmp(char *p1, char *p2)
{
        char c1, c2;

        do {
                if ((c1 = *p1++) == '/')
                        while (*p1 == '/') { p1++; }
                if ((c2 = *p2++) == '/')
                        while (*p2 == '/') { p2++; }
                if (c1 == '\0')
                        return ((c2 == '/') && (*p2 == '\0')) ? 0 : c1 - c2;
        } while (c1 == c2);

        return ((c2 == '\0') && (c1 == '/') && (*p1 == '\0')) ? 0 : c1 - c2;
}

#include <elf.h>

/*
 *  Check the byte-order of an ELF file vs. the host byte order.
 */
int
endian_mismatch(char *file, char dumpfile_endian, ulong query)
{
	char *endian;

	switch (dumpfile_endian)
	{
	case ELFDATA2LSB:
		if (__BYTE_ORDER == __LITTLE_ENDIAN)
			return FALSE;
		endian = "little-endian";
		break;
	case ELFDATA2MSB:
		if (__BYTE_ORDER == __BIG_ENDIAN)	
			return FALSE;
		endian = "big-endian";
		break;
	default:
		endian = "unknown";	
		break;
	}

	if (query == KDUMP_LOCAL)  /* already printed by NETDUMP_LOCAL */
		return TRUE;

        error(WARNING, "endian mismatch:\n");

        fprintf(fp, "         crash utility: %s\n", 
		(__BYTE_ORDER == __LITTLE_ENDIAN) ?
		"little-endian" : "big-endian");
        fprintf(fp, "         %s: %s\n\n", file, endian);

	return TRUE;	
}

uint16_t
swap16(uint16_t val, int swap)
{
	if (swap) 
        	return (((val & 0x00ff) << 8) |
                	((val & 0xff00) >> 8));
	else
		return val;
}

uint32_t
swap32(uint32_t val, int swap)
{
	if (swap)
        	return (((val & 0x000000ffU) << 24) |
                	((val & 0x0000ff00U) <<  8) |
                	((val & 0x00ff0000U) >>  8) |
                	((val & 0xff000000U) >> 24));
	else
		return val;
}

uint64_t
swap64(uint64_t val, int swap)
{
	if (swap)
		return (((val & 0x00000000000000ffULL) << 56) |
			((val & 0x000000000000ff00ULL) << 40) |
			((val & 0x0000000000ff0000ULL) << 24) |
			((val & 0x00000000ff000000ULL) <<  8) |
			((val & 0x000000ff00000000ULL) >>  8) |
			((val & 0x0000ff0000000000ULL) >> 24) |
			((val & 0x00ff000000000000ULL) >> 40) |
			((val & 0xff00000000000000ULL) >> 56));
	else
		return val;
}

/*
 *  Get a sufficiently large buffer for cpumask.
 *  You should call FREEBUF() on the result when you no longer need it.
 */
ulong *
get_cpumask_buf(void)
{
	int cpulen;
	if ((cpulen = STRUCT_SIZE("cpumask_t")) < 0)
		cpulen = DIV_ROUND_UP(kt->cpus, BITS_PER_LONG) * sizeof(ulong);
	return (ulong *)GETBUF(cpulen);
}

int
make_cpumask(char *s, ulong *mask, int flags, int *errptr)
{
	char *p, *q, *orig;
	int start, end;
	int i;

	if (s == NULL) {
		if (!(flags & QUIET))
			error(INFO, "make_cpumask: received NULL string\n");
		orig = NULL;
		goto make_cpumask_error;
	}

	orig = strdup(s);

	p = strtok(s, ",");
	while (p) {
		s = strtok(NULL, "");

		if (STREQ(p, "a") || STREQ(p, "all")) {
			start = 0;
			end = kt->cpus - 1;
		} else {
			start = end = -1;
			q = strtok(p, "-");
			start = dtoi(q, flags, errptr);
			if ((q = strtok(NULL, "-")))
				end = dtoi(q, flags, errptr);

			if (end == -1)
				end = start;
		}
		if ((start < 0) || (start >= kt->cpus) || 
		    (end < 0) || (end >= kt->cpus)) {
			error(INFO, "invalid cpu specification: %s\n", orig);
			goto make_cpumask_error;
		}

		for (i = start; i <= end; i++)
			SET_BIT(mask, i);

		p = strtok(s, ",");
	}

	free(orig);

	return TRUE;

make_cpumask_error:
	free(orig);

	switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	{
	case FAULT_ON_ERROR:
		RESTART();

	case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
	}

	return UNUSED;
}

/*
 * Copy a string into a sized buffer.  If necessary, truncate 
 * the resultant string in the sized buffer so that it will 
 * always be NULL-terminated.
 */
size_t 
strlcpy(char *dest, char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}

struct rb_node *
rb_first(struct rb_root *root)
{
        struct rb_root rloc;
        struct rb_node *n;
	struct rb_node nloc;

	readmem((ulong)root, KVADDR, &rloc, sizeof(struct rb_root), 
		"rb_root", FAULT_ON_ERROR);

        n = rloc.rb_node;
        if (!n)
                return NULL;
        while (rb_left(n, &nloc))
		n = nloc.rb_left;

        return n;
}

struct rb_node *
rb_parent(struct rb_node *node, struct rb_node *nloc)
{
	readmem((ulong)node, KVADDR, nloc, sizeof(struct rb_node), 
		"rb_node", FAULT_ON_ERROR);

	return (struct rb_node *)(nloc->rb_parent_color & ~3);
}

struct rb_node *
rb_right(struct rb_node *node, struct rb_node *nloc)
{
	readmem((ulong)node, KVADDR, nloc, sizeof(struct rb_node), 
		"rb_node", FAULT_ON_ERROR);

	return nloc->rb_right;
}

struct rb_node *
rb_left(struct rb_node *node, struct rb_node *nloc)
{
	readmem((ulong)node, KVADDR, nloc, sizeof(struct rb_node), 
		"rb_node", FAULT_ON_ERROR);

	return nloc->rb_left;
}

struct rb_node *
rb_next(struct rb_node *node)
{
	struct rb_node nloc;
        struct rb_node *parent;

	/* node is destroyed */
	if (!accessible((ulong)node))
		return NULL;

	parent = rb_parent(node, &nloc);

	if (parent == node)
		return NULL;

        if (nloc.rb_right) {
		/* rb_right is destroyed */
		if (!accessible((ulong)nloc.rb_right))
			return NULL;

		node = nloc.rb_right;
		while (rb_left(node, &nloc)) {
			/* rb_left is destroyed */
			if (!accessible((ulong)nloc.rb_left))
				return NULL;
			node = nloc.rb_left;
		}
		return node;
	}

	while ((parent = rb_parent(node, &nloc))) {
		/* parent is destroyed */
                if (!accessible((ulong)parent))
                        return NULL;


		if (node != rb_right(parent, &nloc))
			break;

		node = parent;
	}

        return parent;
}

struct rb_node *
rb_last(struct rb_root *root)
{
	struct rb_node *node;
	struct rb_node nloc;

	/* meet destroyed data */
	if (!accessible((ulong)(root + OFFSET(rb_root_rb_node))))
		return NULL;

	readmem((ulong)(root + OFFSET(rb_root_rb_node)), KVADDR, &node,
		sizeof(node), "rb_root node", FAULT_ON_ERROR);

	while (1) {
		if (!node)
			break;

		/* meet destroyed data */
		if (!accessible((ulong)node))
			return NULL;

		readmem((ulong)node, KVADDR, &nloc, sizeof(struct rb_node),
		"rb_node last", FAULT_ON_ERROR);

		/*  meet the last one  */
		if (!nloc.rb_right)
			break;

		/* meet destroyed data */
		if (!!accessible((ulong)nloc.rb_right))
			break;

		node = nloc.rb_right;
	}

	return node;
}

long
percpu_counter_sum_positive(ulong fbc)
{
	int i, count;
	ulong addr;
	long ret;

	if (INVALID_MEMBER(percpu_counter_count))
		return 0;

	readmem(fbc + OFFSET(percpu_counter_count), KVADDR, &ret,
		sizeof(long long), "percpu_counter.count", FAULT_ON_ERROR);

	if (INVALID_MEMBER(percpu_counter_counters)) /* !CONFIG_SMP */
		return (ret < 0) ? 0 : ret;

	readmem(fbc + OFFSET(percpu_counter_counters), KVADDR, &addr,
		sizeof(void *), "percpu_counter.counters", FAULT_ON_ERROR);

	for (i = 0; i < kt->cpus; i++) {
		readmem(addr + kt->__per_cpu_offset[i], KVADDR, &count,
			sizeof(int), "percpu_counter.counters count", FAULT_ON_ERROR);
		ret += count;
	}

	return (ret < 0) ? 0 : ret;
}
