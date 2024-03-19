// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <stdlib.h>

#include <asm/csr.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sbi.h>

#define RESERVED_CHECK_INCREMENT	10000

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

static void fwft_check_reserved_range(unsigned long start_id,
				      unsigned long end_id)
{
	int ret;
	unsigned long value, i;

	for (i = SBI_FWFT_LOCAL_RESERVED_START; i <= SBI_FWFT_LOCAL_RESERVED_END; i += RESERVED_CHECK_INCREMENT) {

		ret = fwft_get(i, &value);
		if (ret != SBI_ERR_DENIED) {
			report_fail("Reserved feature error == SBI_ERR_DENIED");
			return;
		}

		ret = fwft_set(i, 1, 0);
		if (ret != SBI_ERR_DENIED) {
			report_fail("Reserved feature error == SBI_ERR_DENIED");
			return;
		}
	}

	report_pass("Get reserved feature [0x%lx, 0x%lx] error == SBI_ERR_DENIED",
		    start_id, end_id);
}

static void fwft_check_denied(void)
{
	fwft_check_reserved_range(SBI_FWFT_LOCAL_RESERVED_START, SBI_FWFT_LOCAL_RESERVED_END);
	fwft_check_reserved_range(SBI_FWFT_GLOBAL_RESERVED_START, SBI_FWFT_GLOBAL_RESERVED_END);
}

static bool misaligned_handled = false;

static void misaligned_handler(struct pt_regs *regs)
{
	misaligned_handled = true;
	regs->epc += 4;
}

static void fwft_check_misaligned(void)
{
	int ret;
	unsigned long value;

	report_prefix_push("misaligned_deleg");

	ret = fwft_get(SBI_FWFT_MISALIGNED_DELEG, &value);
	if (ret == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SBI_FWFT_MISALIGNED_DELEG is supported");
	}
	report(!ret, "Get misaligned deleg feature");
	if (ret)
		return;

	/* Set to 0 and check after with get */
	ret = fwft_set(SBI_FWFT_MISALIGNED_DELEG, 0, 0);
	report(!ret, "Set misaligned deleg feature value no error");
	ret = fwft_get(SBI_FWFT_MISALIGNED_DELEG, &value);
	if (ret)
		report_fail("Get misaligned deleg feature after set");
	else
		report(value == 0, "Set misaligned deleg feature value 0");

	/* Set to 1 and check after with get */
	ret = fwft_set(SBI_FWFT_MISALIGNED_DELEG, 1, 0);
	report(!ret, "Set misaligned deleg feature value no error");
	ret = fwft_get(SBI_FWFT_MISALIGNED_DELEG, &value);
	if (ret)
		report_fail("Get misaligned deleg feature after set");
	else
		report(value == 1, "Set misaligned deleg feature value 1");

	install_exception_handler(EXC_LOAD_MISALIGNED, misaligned_handler);

	// asm volatile (
	// 	"lw %[val], 1(%[val_addr])"
	// 	: [val] "+r" (value)
	// 	: [val_addr] "r" (&value)
	// 	: "memory");

	// report(misaligned_handled == true, "Misaligned load exception trapped in supervisor");

	install_exception_handler(EXC_LOAD_MISALIGNED, NULL);

	report_prefix_pop();
}
}

int main(int argc, char **argv)
{
	struct sbiret ret;

	report_prefix_push("sbi");

	report_prefix_push("fwft");

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_FWFT, 0, 0, 0, 0, 0);
	report(!ret.error, "FWFT extension probing no error");
	if (ret.error)
		goto done;

	report(ret.value, "FWFT extension is present");
	if (ret.value == 0)
		goto done;

	fwft_check_denied();
	fwft_check_misaligned();
done:
	report_prefix_pop();

	return report_summary();
}
