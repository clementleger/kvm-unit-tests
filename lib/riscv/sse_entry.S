// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI SSE testsuite
 *
 * Copyright (C) 2023, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>

.global sse_entry
sse_entry:
	/* Save stack temporarily */
	REG_S sp, SSE_REG_TMP(a6)
	/* Set entry stack */
	REG_L sp, SSE_HANDLER_STACK(a6)

	addi sp, sp, -(PT_SIZE)
	REG_S ra, PT_RA(sp)
	REG_S s0, PT_S0(sp)
	REG_S s1, PT_S1(sp)
	REG_S s2, PT_S2(sp)
	REG_S s3, PT_S3(sp)
	REG_S s4, PT_S4(sp)
	REG_S s5, PT_S5(sp)
	REG_S s6, PT_S6(sp)
	REG_S s7, PT_S7(sp)
	REG_S s8, PT_S8(sp)
	REG_S s9, PT_S9(sp)
	REG_S s10, PT_S10(sp)
	REG_S s11, PT_S11(sp)
	REG_S tp, PT_TP(sp)
	REG_S t0, PT_T0(sp)
	REG_S t1, PT_T1(sp)
	REG_S t2, PT_T2(sp)
	REG_S t3, PT_T3(sp)
	REG_S t4, PT_T4(sp)
	REG_S t5, PT_T5(sp)
	REG_S t6, PT_T6(sp)
	REG_S gp, PT_GP(sp)
	REG_S a0, PT_A0(sp)
	REG_S a1, PT_A1(sp)
	REG_S a2, PT_A2(sp)
	REG_S a3, PT_A3(sp)
	REG_S a4, PT_A4(sp)
	REG_S a5, PT_A5(sp)
	csrr a1, CSR_SEPC
	REG_S a1, PT_EPC(sp)
	csrr a2, CSR_SSTATUS
	REG_S a2, PT_STATUS(sp)

	REG_L a0, SSE_REG_TMP(a6)
	REG_S a0, PT_SP(sp)

	REG_L t0, SSE_HANDLER(a6)
	REG_L a0, SSE_HANDLER_DATA(a6)
	move a1, sp
	move a2, a7
	jalr t0


	REG_L a1, PT_EPC(sp)
	REG_L a2, PT_STATUS(sp)
	csrw CSR_SEPC, a1
	csrw CSR_SSTATUS, a2

	REG_L ra, PT_RA(sp)
	REG_L s0, PT_S0(sp)
	REG_L s1, PT_S1(sp)
	REG_L s2, PT_S2(sp)
	REG_L s3, PT_S3(sp)
	REG_L s4, PT_S4(sp)
	REG_L s5, PT_S5(sp)
	REG_L s6, PT_S6(sp)
	REG_L s7, PT_S7(sp)
	REG_L s8, PT_S8(sp)
	REG_L s9, PT_S9(sp)
	REG_L s10, PT_S10(sp)
	REG_L s11, PT_S11(sp)
	REG_L tp, PT_TP(sp)
	REG_L t0, PT_T0(sp)
	REG_L t1, PT_T1(sp)
	REG_L t2, PT_T2(sp)
	REG_L t3, PT_T3(sp)
	REG_L t4, PT_T4(sp)
	REG_L t5, PT_T5(sp)
	REG_L t6, PT_T6(sp)
	REG_L gp, PT_GP(sp)
	REG_L a0, PT_A0(sp)
	REG_L a1, PT_A1(sp)
	REG_L a2, PT_A2(sp)
	REG_L a3, PT_A3(sp)
	REG_L a4, PT_A4(sp)
	REG_L a5, PT_A5(sp)

	REG_L sp, PT_SP(sp)

	li a7, ASM_SBI_EXT_SSE
	li a6, ASM_SBI_EXT_SSE_COMPLETE
	ecall
