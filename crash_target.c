/*
 * crash_target.c
 *
 * Copyright (c) 2021 VMware, Inc.
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
 *
 * Author: Alexey Makhalov <amakhalov@vmware.com>
 */

#include <defs.h>
#include "top.h"
#include "target.h"
#include "inferior.h"
#include "regcache.h"
#include "gdbarch.h"

void crash_target_init (void);

extern "C" int gdb_readmem_callback(unsigned long, void *, int, int);
extern "C" int crash_get_nr_cpus(void);
extern "C" int crash_get_cpu_reg (int cpu, int regno, const char *regname,
                                  int regsize, void *val);


/* The crash target.  */

static const target_info crash_target_info = {
  "crash",
  N_("Local core dump file"),
  N_("Use a built-in crash instance as a target.")
};

class crash_target final : public process_stratum_target
{
public:

  const target_info &info () const override
  { return crash_target_info; }

  void fetch_registers (struct regcache *, int) override;
  enum target_xfer_status xfer_partial (enum target_object object,
                                        const char *annex,
                                        gdb_byte *readbuf,
                                        const gdb_byte *writebuf,
                                        ULONGEST offset, ULONGEST len,
                                        ULONGEST *xfered_len) override;

  bool has_all_memory () override { return true; }
  bool has_memory () override { return true; }
  bool has_stack () override { return true; }
  bool has_registers () override { return true; }
  bool thread_alive (ptid_t ptid) override { return true; }
  std::string pid_to_str (ptid_t ptid) override
  { return string_printf ("CPU %ld", ptid.tid ()); }

};

/* We just get all the registers, so we don't use regno.  */
void
crash_target::fetch_registers (struct regcache *regcache, int regno)
{
  gdb_byte regval[16];
  int cpu = inferior_ptid.tid();
  struct gdbarch *arch = regcache->arch ();

  for (int r = 0; r < gdbarch_num_regs (arch); r++)
    {
      const char *regname = gdbarch_register_name(arch, r);
      int regsize = register_size (arch, r);
      if (regsize > sizeof (regval))
        error (_("fatal error: buffer size is not enough to fit register value"));

      if (crash_get_cpu_reg (cpu, r, regname, regsize, (void *)&regval))
        regcache->raw_supply (r, regval);
      else
        regcache->raw_supply (r, NULL);
    }
}


enum target_xfer_status
crash_target::xfer_partial (enum target_object object, const char *annex,
                           gdb_byte *readbuf, const gdb_byte *writebuf,
                           ULONGEST offset, ULONGEST len, ULONGEST *xfered_len)
{
  if (object != TARGET_OBJECT_MEMORY && object != TARGET_OBJECT_STACK_MEMORY
      && object != TARGET_OBJECT_CODE_MEMORY)
        return TARGET_XFER_E_IO;

  if (gdb_readmem_callback(offset, (void *)(readbuf ? readbuf : writebuf), len, !readbuf))
    {
      *xfered_len = len;
      return TARGET_XFER_OK;
    }

  return TARGET_XFER_E_IO;
}

#define CRASH_INFERIOR_PID 1

void
crash_target_init (void)
{
  int nr_cpus = crash_get_nr_cpus();
  crash_target *target = new crash_target ();

  /* Own the target until it is successfully pushed.  */
  target_ops_up target_holder (target);

  push_target (std::move (target_holder));

  inferior_appeared (current_inferior (), CRASH_INFERIOR_PID);
  for (int i = 0; i < nr_cpus; i++)
    {
      thread_info *thread = add_thread_silent (target,
                                        ptid_t(CRASH_INFERIOR_PID, 0, i));
      if (!i)
        switch_to_thread (thread);
    }

  /* Fetch all registers from core file.  */
  target_fetch_registers (get_current_regcache (), -1);

  /* Now, set up the frame cache. */
  reinit_frame_cache ();
}
