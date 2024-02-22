/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SSE_H_
#define _ASMRISCV_SSE_H_

typedef void (*sse_handler_fn)(void *data, struct pt_regs *regs, unsigned int hartid);

struct sse_handler_arg {
	unsigned long reg_tmp;
	sse_handler_fn handler;
	void *handler_data;
	void *stack;
};

extern void sse_entry(void);

#endif /* _ASMRISCV_SSE_H_ */
