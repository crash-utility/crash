#include "defs.h"
#include <ctype.h>

/* convenience struct for passing many values to helper functions */
struct prb_map {
	char *prb;

	char *desc_ring;
	unsigned long desc_ring_count;
	char *descs;
	char *infos;
	unsigned int pid_max_chars;

	char *text_data_ring;
	unsigned long text_data_ring_size;
	char *text_data;
};

/*
 * desc_state and DESC_* definitions taken from kernel source:
 *
 * kernel/printk/printk_ringbuffer.h
 */

/* The possible responses of a descriptor state-query. */
enum desc_state {
	desc_miss	=  -1,	/* ID mismatch (pseudo state) */
	desc_reserved	= 0x0,	/* reserved, in use by writer */
	desc_committed	= 0x1,	/* committed by writer, could get reopened */
	desc_finalized	= 0x2,	/* committed, no further modification allowed */
	desc_reusable	= 0x3,	/* free, not yet used by any writer */
};

#define DESC_SV_BITS		(sizeof(unsigned long) * 8)
#define DESC_FLAGS_SHIFT	(DESC_SV_BITS - 2)
#define DESC_FLAGS_MASK		(3UL << DESC_FLAGS_SHIFT)
#define DESC_STATE(sv)		(3UL & (sv >> DESC_FLAGS_SHIFT))
#define DESC_ID_MASK		(~DESC_FLAGS_MASK)
#define DESC_ID(sv)		((sv) & DESC_ID_MASK)

/*
 * get_desc_state() taken from kernel source:
 *
 * kernel/printk/printk_ringbuffer.c
 */

/* Query the state of a descriptor. */
static enum desc_state get_desc_state(unsigned long id,
				      unsigned long state_val)
{
	if (id != DESC_ID(state_val))
		return desc_miss;

	return DESC_STATE(state_val);
}

static void
init_offsets(void)
{
	char *n;

	n = "printk_info";
	STRUCT_SIZE_INIT(printk_info, n);
	MEMBER_OFFSET_INIT(printk_info_seq, n, "seq");
	MEMBER_OFFSET_INIT(printk_info_ts_nsec, n, "ts_nsec");
	MEMBER_OFFSET_INIT(printk_info_text_len, n, "text_len");
	MEMBER_OFFSET_INIT(printk_info_level, n, "level");
	MEMBER_OFFSET_INIT(printk_info_caller_id, n, "caller_id");
	MEMBER_OFFSET_INIT(printk_info_dev_info, n, "dev_info");

	n = "dev_printk_info";
	MEMBER_OFFSET_INIT(dev_printk_info_subsystem, n, "subsystem");
	MEMBER_OFFSET_INIT(dev_printk_info_device, n, "device");

	n = "printk_ringbuffer";
	STRUCT_SIZE_INIT(printk_ringbuffer, n);
	MEMBER_OFFSET_INIT(prb_desc_ring, n, "desc_ring");
	MEMBER_OFFSET_INIT(prb_text_data_ring, n, "text_data_ring");

	n = "prb_desc_ring";
	MEMBER_OFFSET_INIT(prb_desc_ring_count_bits, n, "count_bits");
	MEMBER_OFFSET_INIT(prb_desc_ring_descs, n, "descs");
	MEMBER_OFFSET_INIT(prb_desc_ring_infos, n, "infos");
	MEMBER_OFFSET_INIT(prb_desc_ring_head_id, n, "head_id");
	MEMBER_OFFSET_INIT(prb_desc_ring_tail_id, n, "tail_id");

	n = "prb_desc";
	STRUCT_SIZE_INIT(prb_desc, n);
	MEMBER_OFFSET_INIT(prb_desc_state_var, n, "state_var");
	MEMBER_OFFSET_INIT(prb_desc_text_blk_lpos, n, "text_blk_lpos");

	n = "prb_data_blk_lpos";
	MEMBER_OFFSET_INIT(prb_data_blk_lpos_begin, n, "begin");
	MEMBER_OFFSET_INIT(prb_data_blk_lpos_next, n, "next");

	n = "prb_data_ring";
	MEMBER_OFFSET_INIT(prb_data_ring_size_bits, n, "size_bits");
	MEMBER_OFFSET_INIT(prb_data_ring_data, n, "data");

	n = "atomic_long_t";
	MEMBER_OFFSET_INIT(atomic_long_t_counter, n, "counter");
}

static void
dump_record(struct prb_map *m, unsigned long id, int msg_flags)
{
	unsigned short text_len;
	unsigned long state_var;
	unsigned int caller_id;
	enum desc_state state;
	unsigned char level;
	unsigned long begin;
	unsigned long next;
	char buf[BUFSIZE];
	uint64_t ts_nsec;
	ulonglong nanos;
	ulonglong seq;
	int ilen = 0, i;
	char *desc, *info, *text, *p;
	ulong rem;

	desc = m->descs + ((id % m->desc_ring_count) * SIZE(prb_desc));

	/* skip non-committed record */
	state_var = ULONG(desc + OFFSET(prb_desc_state_var) +
			OFFSET(atomic_long_t_counter));
	state = get_desc_state(id, state_var);
	if (state != desc_committed && state != desc_finalized)
		return;

	info = m->infos + ((id % m->desc_ring_count) * SIZE(printk_info));

	seq = ULONGLONG(info + OFFSET(printk_info_seq));
	caller_id = UINT(info + OFFSET(printk_info_caller_id));
	if (CRASHDEBUG(1))
		fprintf(fp, "seq: %llu caller_id: %x (%s: %u)\n", seq, caller_id,
			caller_id & 0x80000000 ? "cpu" : "pid", caller_id & ~0x80000000);

	text_len = USHORT(info + OFFSET(printk_info_text_len));

	begin = ULONG(desc + OFFSET(prb_desc_text_blk_lpos) +
		      OFFSET(prb_data_blk_lpos_begin)) %
			m->text_data_ring_size;
	next = ULONG(desc + OFFSET(prb_desc_text_blk_lpos) +
		     OFFSET(prb_data_blk_lpos_next)) %
			m->text_data_ring_size;

	/* skip data-less text blocks */
	if (begin == next)
		goto out;

	if ((msg_flags & SHOW_LOG_TEXT) == 0) {
		ts_nsec = ULONGLONG(info + OFFSET(printk_info_ts_nsec));
		nanos = (ulonglong)ts_nsec / (ulonglong)1000000000;
		rem = (ulonglong)ts_nsec % (ulonglong)1000000000;
		if (msg_flags & SHOW_LOG_CTIME) {
			time_t t = kt->boot_date.tv_sec + nanos;
			sprintf(buf, "[%s] ", ctime_tz(&t));
		} else
			sprintf(buf, "[%5lld.%06ld] ", nanos, rem/1000);

		ilen += strlen(buf);
		fprintf(fp, "%s", buf);
	}

	/*
	 * The lockless ringbuffer introduced in Linux-5.10 always has
	 * the caller_id field available, so if requested, print it.
	 */
	if (msg_flags & SHOW_LOG_CALLER) {
		const unsigned int cpuid = 0x80000000;
		char cbuf[PID_CHARS_MAX];
		unsigned int cid;

		/* Get id type, isolate id value in cid for print */
		cid = UINT(info + OFFSET(printk_info_caller_id));
		sprintf(cbuf, "%c%d", (cid & cpuid) ? 'C' : 'T', cid & ~cpuid);
		sprintf(buf, "[%*s] ", m->pid_max_chars, cbuf);

		ilen += strlen(buf);
		fprintf(fp, "%s", buf);
	}

	if (msg_flags & SHOW_LOG_LEVEL) {
		level = UCHAR(info + OFFSET(printk_info_level)) >> 5;
		sprintf(buf, "<%x>", level);
		ilen += strlen(buf);
		fprintf(fp, "%s", buf);
	}

	/* handle wrapping data block */
	if (begin > next)
		begin = 0;

	/* skip over descriptor ID */
	begin += sizeof(unsigned long);

	/* handle truncated messages */
	if (next - begin < text_len)
		text_len = next - begin;

	text = m->text_data + begin;

	for (i = 0, p = text; i < text_len; i++, p++) {
		if (*p == '\n')
			fprintf(fp, "\n%s", space(ilen));
		else if (isprint(*p) || isspace(*p))
			fputc(*p, fp);
		else
			fputc('.', fp);
	}

	if (msg_flags & SHOW_LOG_DICT) {
		text = info + OFFSET(printk_info_dev_info) +
				OFFSET(dev_printk_info_subsystem);
		if (strlen(text))
			fprintf(fp, "\n%sSUBSYSTEM=%s", space(ilen), text);

		text = info + OFFSET(printk_info_dev_info) +
				OFFSET(dev_printk_info_device);
		if (strlen(text))
			fprintf(fp, "\n%sDEVICE=%s", space(ilen), text);
	}
out:
	fprintf(fp, "\n");
}

/*
 *  Handle the lockless printk_ringbuffer.
 */
void
dump_lockless_record_log(int msg_flags)
{
	unsigned long head_id;
	unsigned long tail_id;
	unsigned long kaddr;
	unsigned long id;
	struct prb_map m;

	if (INVALID_SIZE(printk_info))
		init_offsets();

	/* setup printk_ringbuffer */
	get_symbol_data("prb", sizeof(char *), &kaddr);
	m.prb = GETBUF(SIZE(printk_ringbuffer));
	if (!readmem(kaddr, KVADDR, m.prb, SIZE(printk_ringbuffer),
		     "printk_ringbuffer contents", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "\ncannot read printk_ringbuffer contents\n");
		goto out_prb;
	}

	/* setup descriptor ring */
	m.desc_ring = m.prb + OFFSET(prb_desc_ring);
	m.desc_ring_count = 1 << UINT(m.desc_ring + OFFSET(prb_desc_ring_count_bits));

	kaddr = ULONG(m.desc_ring + OFFSET(prb_desc_ring_descs));
	m.descs = GETBUF(SIZE(prb_desc) * m.desc_ring_count);
	if (!readmem(kaddr, KVADDR, m.descs, SIZE(prb_desc) * m.desc_ring_count,
		     "prb_desc_ring contents", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "\ncannot read prb_desc_ring contents\n");
		goto out_descs;
	}

	kaddr = ULONG(m.desc_ring + OFFSET(prb_desc_ring_infos));
	m.infos = GETBUF(SIZE(printk_info) * m.desc_ring_count);
	if (!readmem(kaddr, KVADDR, m.infos, SIZE(printk_info) * m.desc_ring_count,
		     "prb_info_ring contents", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "\ncannot read prb_info_ring contents\n");
		goto out_infos;
	}

	/* setup text data ring */
	m.text_data_ring = m.prb + OFFSET(prb_text_data_ring);
	m.text_data_ring_size = 1 << UINT(m.text_data_ring + OFFSET(prb_data_ring_size_bits));

	kaddr = ULONG(m.text_data_ring + OFFSET(prb_data_ring_data));
	m.text_data = GETBUF(m.text_data_ring_size);
	if (!readmem(kaddr, KVADDR, m.text_data, m.text_data_ring_size,
		     "prb_text_data_ring contents", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "\ncannot read prb_text_data_ring contents\n");
		goto out_text_data;
	}

	/* If caller_id was requested, get the pid_max value for print */
	if (msg_flags & SHOW_LOG_CALLER) {
		unsigned int pidmax;

		get_symbol_data("pid_max", sizeof(pidmax), &pidmax);
		if (pidmax <= 99999)
			m.pid_max_chars = 6;
		else if (pidmax <= 999999)
			m.pid_max_chars = 7;
		else
			m.pid_max_chars = PID_CHARS_DEFAULT;
	} else {
		m.pid_max_chars = PID_CHARS_DEFAULT;
	}

	/* ready to go */

	tail_id = ULONG(m.desc_ring + OFFSET(prb_desc_ring_tail_id) +
			OFFSET(atomic_long_t_counter));
	head_id = ULONG(m.desc_ring + OFFSET(prb_desc_ring_head_id) +
			OFFSET(atomic_long_t_counter));

	hq_open();

	for (id = tail_id; id != head_id; id = (id + 1) & DESC_ID_MASK)
		dump_record(&m, id, msg_flags);

	/* dump head record */
	dump_record(&m, id, msg_flags);

	hq_close();

out_text_data:
	FREEBUF(m.text_data);
out_infos:
	FREEBUF(m.infos);
out_descs:
	FREEBUF(m.descs);
out_prb:
	FREEBUF(m.prb);
}
