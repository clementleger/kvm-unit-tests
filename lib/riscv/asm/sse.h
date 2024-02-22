/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SSE_H_
#define _ASMRISCV_SSE_H_

struct sse_handler_arg {
	void (*handler)(void *data);
	void *handler_data;
	void *stack;
};

extern void sse_entry(void);

#endif /* _ASMRISCV_SSE_H_ */