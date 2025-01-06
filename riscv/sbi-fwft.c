// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2024, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <libcflat.h>
#include <stdlib.h>

#include <asm/csr.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sbi.h>

#define RESERVED_CHECK_INCREMENT	10000

void check_fwft(void);

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

static void fwft_check_reserved(unsigned long id)
{
	int ret;
	bool pass = true;
	unsigned long value;

	ret = fwft_get(id, &value);
	if (ret != SBI_ERR_DENIED) {
		pass = false;
	}

	ret = fwft_set(id, 1, 0);
	if (ret != SBI_ERR_DENIED) {
		pass = false;
	}

	report(pass, "get/set reserved feature 0x%lx error == SBI_ERR_DENIED", id);
}

static void fwft_check_denied(void)
{
	fwft_check_reserved(SBI_FWFT_LOCAL_RESERVED_START);
	fwft_check_reserved(SBI_FWFT_LOCAL_RESERVED_END);
	fwft_check_reserved(SBI_FWFT_GLOBAL_RESERVED_START);
	fwft_check_reserved(SBI_FWFT_GLOBAL_RESERVED_END);
}

static bool misaligned_handled;

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

	ret = fwft_get(SBI_FWFT_MISALIGNED_EXC_DELEG, &value);
	if (ret == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SBI_FWFT_MISALIGNED_EXC_DELEG is not supported");
		return;
	}
	report(!ret, "Get misaligned deleg feature no error");
	if (ret)
		return;

	ret = fwft_set(SBI_FWFT_MISALIGNED_EXC_DELEG, 2, 0);
	report(ret == SBI_ERR_INVALID_PARAM, "Set misaligned deleg feature invalid value error");
	ret = fwft_set(SBI_FWFT_MISALIGNED_EXC_DELEG, 0xFFFFFFFF, 0);
	report(ret == SBI_ERR_INVALID_PARAM, "Set misaligned deleg feature invalid value error");

	/* Set to 0 and check after with get */
	ret = fwft_set(SBI_FWFT_MISALIGNED_EXC_DELEG, 0, 0);
	report(!ret, "Set misaligned deleg feature value no error");
	ret = fwft_get(SBI_FWFT_MISALIGNED_EXC_DELEG, &value);
	if (ret)
		report_fail("Get misaligned deleg feature after set");
	else
		report(value == 0, "Set misaligned deleg feature value 0");

	/* Set to 1 and check after with get */
	ret = fwft_set(SBI_FWFT_MISALIGNED_EXC_DELEG, 1, 0);
	report(!ret, "Set misaligned deleg feature value no error");
	ret = fwft_get(SBI_FWFT_MISALIGNED_EXC_DELEG, &value);
	if (ret)
		report_fail("Get misaligned deleg feature after set");
	else
		report(value == 1, "Set misaligned deleg feature value 1");

	install_exception_handler(EXC_LOAD_MISALIGNED, misaligned_handler);

	asm volatile (
		".option norvc\n"
		"lw %[val], 1(%[val_addr])"
		: [val] "+r" (value)
		: [val_addr] "r" (&value)
		: "memory");

	if (!misaligned_handled)
		report_skip("Verify misaligned load exception trap in supervisor");
	else
		report_pass("Verify misaligned load exception trap in supervisor");

	install_exception_handler(EXC_LOAD_MISALIGNED, NULL);

	report_prefix_pop();
}

void check_fwft(void)
{
	struct sbiret ret;

	report_prefix_push("fwft");

	if (!sbi_probe(SBI_EXT_FWFT)) {
		report_skip("FWFT extension not available");
		report_prefix_pop();
		return;
	}

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_FWFT, 0, 0, 0, 0, 0);
	report(!ret.error, "FWFT extension probing no error");
	if (ret.error)
		goto done;

	if (ret.value == 0) {
		report_skip("FWFT extension is not present");
		goto done;
	}

	fwft_check_denied();
	fwft_check_misaligned();
done:
	report_prefix_pop();
}
