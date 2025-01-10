// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <alloc.h>
#include <alloc_page.h>
#include <libcflat.h>
#include <stdlib.h>

#include <asm/csr.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sbi.h>

#include "sse.h"

static int fwft_set(unsigned long feature_id, unsigned long value,
		       unsigned long flags)
{
	struct sbiret ret = sbi_ecall(SBI_EXT_FWFT, SBI_EXT_FWFT_SET,
				      feature_id, value, flags, 0, 0, 0);

	return ret.error;
}

static int fwft_get(unsigned long feature_id, unsigned long *value)
{
	struct sbiret ret = sbi_ecall(SBI_EXT_FWFT, SBI_EXT_FWFT_GET,
				      feature_id, 0, 0, 0, 0, 0);

	*value = ret.value;

	return ret.error;
}

static bool double_break = false;
static bool set_sdt = true;

static void break_handler(struct pt_regs *regs)
{

	if (set_sdt)
		csr_set(CSR_SSTATUS, SR_SDT);

	if (double_break) {
		double_break = false;
		asm volatile ("ebreak\n");
	}

	/* Skip break instruction */
	regs->epc += 2;
}

static bool sse_dbltrp_called = false;

static void sse_dbltrp_handler(void *data, struct pt_regs *regs,
			       unsigned int hartid)
{
	sse_dbltrp_called = true;
	regs->epc += 2;
}

static void sse_double_trap(void)
{
	unsigned long ret;

	struct sse_handler_arg handler_arg = {
		.handler = sse_dbltrp_handler,
		.stack = alloc_page() + PAGE_SIZE,
	};

	report_prefix_push("sse");

	ret = sse_hart_unmask();
	assert(ret == 0);

	ret = sse_event_register(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP, &handler_arg);
	if (ret == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SSE double trap event is not supported");
		goto out;
	}
	ret = sse_event_enable(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP);
	assert(ret == SBI_SUCCESS);

	set_sdt = true;
	double_break = true;
	asm volatile ("ebreak\n");

	report(sse_dbltrp_called, "SSE double trap event generated");

	ret = sse_event_disable(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP);
	assert(ret == SBI_SUCCESS);
	ret = sse_event_unregister(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP);
	assert(ret == SBI_SUCCESS);

out:
	free_page(handler_arg.stack - PAGE_SIZE);

	report_prefix_pop();
}

static void check_double_trap(void)
{
	int ret;
	unsigned long value = 0;

	/* Disable double trap */
	ret = fwft_set(SBI_FWFT_DOUBLE_TRAP, 0, 0);
	report(!ret, "Set double trap enable feature value == 0");
	ret = fwft_get(SBI_FWFT_DOUBLE_TRAP, &value);
	report(value == 0, "Get double trap enable feature value == 0");

	install_exception_handler(EXC_BREAKPOINT, break_handler);

	double_break = true;
	asm volatile ("ebreak\n");
	report_pass("Double trap disabled, trap first time ok");

	/* Enable double trap */
	ret = fwft_set(SBI_FWFT_DOUBLE_TRAP, 1, 1);
	report(!ret, "Set double trap enable feature value == 1");
	ret = fwft_get(SBI_FWFT_DOUBLE_TRAP, &value);
	report(value == 1, "Get double trap enable feature value == 1");
	csr_clear(CSR_SSTATUS, SR_SDT);

	/* First time, clear the double trap flag (SDT) */
	set_sdt = false;
	double_break = true;
	asm volatile ("ebreak\n");
	report_pass("Trapped twice allowed ok");

	if (sbi_probe(SBI_EXT_SSE)) {
		sse_double_trap();
	} else {
		report_skip("SSE double trap event will not be tested, extension is not available");
	}

	/* Second time, keep the double trap flag (SDT) and generate another
	 * trap
	 */
	set_sdt = true;
	double_break = true;
	report_info("Should generate a double trap and crash !");
	asm volatile ("ebreak\n");
	report_fail("Should have crashed !");
}

int main(int argc, char **argv)
{
	int ret;
	unsigned long value;
	report_prefix_push("dbltrp");

	if (!sbi_probe(SBI_EXT_FWFT)) {
		report_skip("FWFT extension is not available");
		goto out;
	}

	ret = fwft_get(SBI_FWFT_DOUBLE_TRAP, &value);
	if (ret == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SBI_FWFT_DOUBLE_TRAP is not supported !");
		goto out;
	}

	check_double_trap();
out:
	report_prefix_pop();

	return report_summary();
}
