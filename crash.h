#ifdef CRASH_MERGE
#define GDB_COMMON
#include "defs.h"
#include "symtab.h"
#include "interps.h"
struct ui_file;
void gdb_bait_and_switch(char *, struct symbol *);
struct block *gdb_get_crash_block(void);
extern int gdb_main_entry(int, char **);
extern void replace_ui_file_FILE(struct ui_file *, FILE *);
int crash_validate_source_file(const char *path, FILE *stream, int from_tty);
extern const struct interp_procs *cli_procs;
#endif
