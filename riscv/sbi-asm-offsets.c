// SPDX-License-Identifier: GPL-2.0-only
#include <kbuild.h>
#include <asm/sbi.h>
#include "sbi-tests.h"
#include "sse.h"

int main(void)
{
	DEFINE(ASM_SBI_EXT_HSM, SBI_EXT_HSM);
	DEFINE(ASM_SBI_EXT_HSM_HART_STOP, SBI_EXT_HSM_HART_STOP);
	DEFINE(ASM_SBI_EXT_SSE, SBI_EXT_SSE);
	DEFINE(ASM_SBI_EXT_SSE_COMPLETE, SBI_EXT_SSE_COMPLETE);

	OFFSET(SBI_SSE_REG_TMP, sse_handler_arg, reg_tmp);
	OFFSET(SBI_SSE_HANDLER, sse_handler_arg, handler);
	OFFSET(SBI_SSE_HANDLER_DATA, sse_handler_arg, handler_data);
	OFFSET(SBI_SSE_HANDLER_STACK, sse_handler_arg, stack);

	return 0;
}
