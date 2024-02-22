// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI SSE testsuite
 *
 * Copyright (C) 2024, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <asm/sbi.h>

#include "sse.h"

bool sse_event_is_global(unsigned long event_id)
{
	return !!(event_id & SBI_SSE_EVENT_GLOBAL_BIT);
}

struct sbiret sse_event_get_attr_raw(unsigned long event_id,
					    unsigned long base_attr_id,
					    unsigned long attr_count,
					    unsigned long phys_lo,
					    unsigned long phys_hi)
{
	return sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_READ_ATTRS, event_id,
			base_attr_id, attr_count, phys_lo, phys_hi, 0);
}

unsigned long sse_event_get_attrs(unsigned long event_id, unsigned long attr_id,
					 unsigned long *values, unsigned int attr_count)
{
	struct sbiret ret;

	ret = sse_event_get_attr_raw(event_id, attr_id, attr_count, (unsigned long)values, 0);

	return ret.error;
}

unsigned long sse_event_get_attr(unsigned long event_id, unsigned long attr_id,
					unsigned long *value)
{
	return sse_event_get_attrs(event_id, attr_id, value, 1);
}

struct sbiret sse_event_set_attr_raw(unsigned long event_id, unsigned long base_attr_id,
					    unsigned long attr_count, unsigned long phys_lo,
					    unsigned long phys_hi)
{
	return sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_WRITE_ATTRS, event_id, base_attr_id, attr_count,
			 phys_lo, phys_hi, 0);
}

unsigned long sse_event_set_attr(unsigned long event_id, unsigned long attr_id,
					unsigned long value)
{
	struct sbiret ret;

	ret = sse_event_set_attr_raw(event_id, attr_id, 1, (unsigned long)&value, 0);

	return ret.error;
}

unsigned long sse_event_register_raw(unsigned long event_id, void *entry_pc, void *entry_arg)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_REGISTER, event_id, (unsigned long)entry_pc,
			(unsigned long)entry_arg, 0, 0, 0);

	return ret.error;
}

unsigned long sse_event_register(unsigned long event_id, struct sse_handler_arg *arg)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_REGISTER, event_id, (unsigned long)sse_entry,
			(unsigned long)arg, 0, 0, 0);

	return ret.error;
}

unsigned long sse_event_unregister(unsigned long event_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_UNREGISTER, event_id, 0, 0, 0, 0, 0);

	return ret.error;
}

unsigned long sse_event_enable(unsigned long event_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_ENABLE, event_id, 0, 0, 0, 0, 0);

	return ret.error;
}

unsigned long sse_hart_mask(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_HART_MASK, 0, 0, 0, 0, 0, 0);

	return ret.error;
}

unsigned long sse_hart_unmask(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_HART_UNMASK, 0, 0, 0, 0, 0, 0);

	return ret.error;
}

unsigned long sse_event_inject(unsigned long event_id, unsigned long hart_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_INJECT, event_id, hart_id, 0, 0, 0, 0);

	return ret.error;
}

unsigned long sse_event_disable(unsigned long event_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_DISABLE, event_id, 0, 0, 0, 0, 0);

	return ret.error;
}
