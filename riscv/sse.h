/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RISCV_SSE_H_
#define _RISCV_SSE_H_

#include <asm/sbi.h>

typedef void (*sse_handler_fn)(void *data, struct pt_regs *regs, unsigned int hartid);

struct sse_handler_arg {
	unsigned long reg_tmp;
	sse_handler_fn handler;
	void *handler_data;
	void *stack;
};

extern void sse_entry(void);

bool sse_event_is_global(unsigned long event_id);

struct sbiret sse_event_get_attr_raw(unsigned long event_id, unsigned long base_attr_id,
				     unsigned long attr_count, unsigned long phys_lo,
				     unsigned long phys_hi);
unsigned long sse_event_get_attrs(unsigned long event_id, unsigned long attr_id,
				  unsigned long *values, unsigned int attr_count);
unsigned long sse_event_get_attr(unsigned long event_id, unsigned long attr_id,
				 unsigned long *value);
struct sbiret sse_event_set_attr_raw(unsigned long event_id, unsigned long base_attr_id,
				     unsigned long attr_count, unsigned long phys_lo,
				     unsigned long phys_hi);
unsigned long sse_event_set_attr(unsigned long event_id, unsigned long attr_id,
				 unsigned long value);
unsigned long sse_event_register_raw(unsigned long event_id, void *entry_pc, void *entry_arg);
unsigned long sse_event_register(unsigned long event_id, struct sse_handler_arg *arg);
unsigned long sse_event_unregister(unsigned long event_id);
unsigned long sse_event_enable(unsigned long event_id);
unsigned long sse_hart_mask(void);
unsigned long sse_hart_unmask(void);
unsigned long sse_event_inject(unsigned long event_id, unsigned long hart_id);
unsigned long sse_event_disable(unsigned long event_id);

#endif /* !_RISCV_SSE_H_ */