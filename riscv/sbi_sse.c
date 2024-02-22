// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI SSE testsuite
 *
 * Copyright (C) 2023, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <libcflat.h>
#include <alloc_page.h>
#include <bitops.h>
#include <cpumask.h>
#include <libcflat.h>
#include <on-cpus.h>
#include <alloc.h>

#include <asm/barrier.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/setup.h>
#include <asm/sse.h>

#define SSE_STACK_SIZE	PAGE_SIZE

#define INJECT_A2_VAL	0xDEAD0001
#define INJECT_A3_VAL	0xDEAD0002
#define INJECT_A4_VAL	0xDEAD0003
#define INJECT_A5_VAL	0xDEAD0004

struct sse_event_info {
	unsigned long event_id;
	const char *name;
	bool can_inject;
};

static struct sse_event_info sse_event_infos[] = {
	{
		.event_id = SBI_SSE_EVENT_LOCAL_RAS,
		.name = "local_ras",
		.can_inject = true
	},
	{
		.event_id = SBI_SSE_EVENT_GLOBAL_RAS,
		.name = "global_ras",
		.can_inject = true
	},
	{
		.event_id = SBI_SSE_EVENT_LOCAL_PMU,
		.name = "local_pmu",
		.can_inject = true
	},
	{
		.event_id = SBI_SSE_EVENT_LOCAL_SOFTWARE,
		.name = "local_software",
		.can_inject = true
	},
	{
		.event_id = SBI_SSE_EVENT_GLOBAL_SOFTWARE,
		.name = "global_software",
		.can_inject = true
	},
};

static const char *attr_names[] = {
	[SBI_SSE_ATTR_STATUS] = "status",
	[SBI_SSE_ATTR_PRIO] = "prio",
	[SBI_SSE_ATTR_CONFIG] = "config",
	[SBI_SSE_ATTR_PREFERRED_HART] = "preferred_hart",
	[SBI_SSE_ATTR_ENTRY_PC] = "entry_pc",
	[SBI_SSE_ATTR_ENTRY_ARG] = "entry_arg",
	[SBI_SSE_ATTR_INTERRUPTED_SEPC] = "interrupted_pc",
	[SBI_SSE_ATTR_INTERRUPTED_FLAGS] = "interrupted_flags",
	[SBI_SSE_ATTR_INTERRUPTED_A6] = "interrupted_a6",
	[SBI_SSE_ATTR_INTERRUPTED_A7] = "interrupted_a7",
};

static const unsigned long ro_attrs[] = {
	SBI_SSE_ATTR_STATUS,
	SBI_SSE_ATTR_ENTRY_PC,
	SBI_SSE_ATTR_ENTRY_ARG,
	SBI_SSE_ATTR_INTERRUPTED_SEPC,
	SBI_SSE_ATTR_INTERRUPTED_FLAGS,
	SBI_SSE_ATTR_INTERRUPTED_A6,
	SBI_SSE_ATTR_INTERRUPTED_A7,
};

static void help(void)
{
	puts("Test SBI SSE extension\n");
}

static struct sse_event_info *sse_evt_get_infos(unsigned long event_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sse_event_infos); i++) {
		if (sse_event_infos[i].event_id == event_id)
			return &sse_event_infos[i];
	}

	assert_msg(false, "Invalid event id: %ld", event_id);
}

static const char *sse_evt_name(unsigned long event_id)
{
	struct sse_event_info *infos = sse_evt_get_infos(event_id);

	return infos->name;
}

static bool sse_evt_can_inject(unsigned long event_id)
{
	struct sse_event_info *infos = sse_evt_get_infos(event_id);

	return infos->can_inject;
}

static bool sse_event_is_global(unsigned long event_id)
{
	return !!(event_id & SBI_SSE_EVENT_GLOBAL_BIT);
}

static struct sbiret sse_event_get_attr_raw(unsigned long event_id,
					    unsigned long base_attr_id,
					    unsigned long attr_count,
					    unsigned long phys_lo,
					    unsigned long phys_hi)
{
	return sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_READ_ATTR, event_id,
			base_attr_id, attr_count, phys_lo, phys_hi, 0);
}

static unsigned long sse_event_get_attrs(unsigned long event_id, unsigned long attr_id, unsigned long *values, unsigned int attr_count)
{
	struct sbiret ret;

	ret = sse_event_get_attr_raw(event_id, attr_id, attr_count, (unsigned long)values, 0);

	return ret.error;
}

static unsigned long sse_event_get_attr(unsigned long event_id, unsigned long attr_id, unsigned long *value)
{
	return sse_event_get_attrs(event_id, attr_id, value, 1);
}

static struct sbiret sse_event_set_attr_raw(unsigned long event_id,
					    unsigned long base_attr_id,
					    unsigned long attr_count,
					    unsigned long phys_lo,
					    unsigned long phys_hi)
{
	return sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_WRITE_ATTR, event_id,
			base_attr_id, attr_count, phys_lo, phys_hi, 0);
}

static unsigned long sse_event_set_attr(unsigned long event_id, unsigned long attr_id, unsigned long value)
{
	struct sbiret ret;

	ret = sse_event_set_attr_raw(event_id, attr_id, 1, (unsigned long)&value, 0);

	return ret.error;
}

static unsigned long sse_event_register_raw(unsigned long event_id, void *entry_pc, void *entry_arg)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_REGISTER, event_id,
			(unsigned long)entry_pc, (unsigned long)entry_arg, 0, 0,
			0);

	return ret.error;
}

static unsigned long sse_event_register(unsigned long event_id, struct sse_handler_arg *arg)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_REGISTER, event_id,
			(unsigned long)sse_entry, (unsigned long)arg, 0, 0,
			0);

	return ret.error;
}

static unsigned long sse_event_unregister(unsigned long event_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_UNREGISTER, event_id, 0, 0, 0, 0, 0);

	return ret.error;
}

static unsigned long sse_event_enable(unsigned long event_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_ENABLE, event_id, 0, 0, 0, 0, 0);

	return ret.error;
}

static unsigned long sse_event_inject(unsigned long event_id, unsigned long hart_id)
{
	struct sbiret ret;

	/* Note: we explicitely set a2, a3, a4 and a5 to dummy value in order to
	 * check for their values to be correct in simple handler */
	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_INJECT, event_id, hart_id,
			INJECT_A2_VAL, INJECT_A3_VAL, INJECT_A4_VAL,
			INJECT_A5_VAL);

	return ret.error;
}

static unsigned long sse_event_disable(unsigned long event_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_EXT_SSE_DISABLE, event_id, 0, 0, 0, 0, 0);

	return ret.error;
}


static int sse_get_state(unsigned long event_id, enum sbi_sse_state *state)
{
	int ret;
	unsigned long status;

	ret = sse_event_get_attr(event_id, SBI_SSE_ATTR_STATUS, &status);
	if (ret) {
		report_fail("Failed to get SSE event status");
		return -1;
	}

	*state = status & SBI_SSE_ATTR_STATUS_STATE_MASK;

	return 0;
}

static void sse_global_event_set_current_hart(unsigned long event_id)
{
	int ret;

	if (!sse_event_is_global(event_id))
		return;

	ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_PREFERRED_HART, current_thread_info()->hartid);
	if (ret)
		report_abort("set preferred hart failure");
}

static int sse_check_state(unsigned long event_id, unsigned long expected_state)
{
	int ret;
	enum sbi_sse_state state;

	ret = sse_get_state(event_id, &state);
	if (ret)
		return 1;
	report(state == expected_state,
	       "SSE event status == %ld", expected_state);

	return state != expected_state;
}

static bool sse_event_pending(unsigned long event_id)
{
	int ret;
	unsigned long status;

	ret = sse_event_get_attr(event_id, SBI_SSE_ATTR_STATUS, &status);
	if (ret) {
		report_fail("Failed to get SSE event status");
		return -1;
	}

	return !!(status & BIT(SBI_SSE_ATTR_STATUS_PENDING_OFFSET));
}

static void *sse_alloc_stack(void)
{
	return (alloc_page() + PAGE_SIZE);
}

static void sse_free_stack(void *stack)
{
	free_page(stack - PAGE_SIZE);
}

static void sse_test_attr(unsigned long event_id)
{
	unsigned long ret, value = 0;
	unsigned long values[ARRAY_SIZE(ro_attrs)];
	struct sbiret sret;
	unsigned int i;

	report_prefix_push("attrs");

	for (i = 0; i < ARRAY_SIZE(ro_attrs); i++) {
		ret = sse_event_set_attr(event_id, ro_attrs[i], value);
		report(ret == SBI_ERR_BAD_RANGE, "RO attribute %s not writable",
		       attr_names[ro_attrs[i]]);
	}

	for (i = SBI_SSE_ATTR_STATUS; i <= SBI_SSE_ATTR_INTERRUPTED_A7; i++) {
		ret = sse_event_get_attr(event_id, i, &value);
		report(ret == SBI_SUCCESS, "Read single attribute %s", attr_names[i]);
		/* Preferred Hart reset value is defined by SBI vendor and status injectable bit
		 * also depends on the SBI implementation
		 */
		if (i != SBI_SSE_ATTR_STATUS && i != SBI_SSE_ATTR_PREFERRED_HART)
			report(value == 0, "Attribute %s reset value is 0", attr_names[i]);
	}

	ret = sse_event_get_attrs(event_id, SBI_SSE_ATTR_STATUS, values, SBI_SSE_ATTR_INTERRUPTED_A7 - SBI_SSE_ATTR_STATUS);
	report(ret == SBI_SUCCESS, "Read multiple RO attribute");

#if __riscv_xlen > 32
	ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_PRIO, 0xFFFFFFFFUL + 1UL);
	report(ret == SBI_ERR_INVALID_PARAM, "Write prio > 0xFFFFFFFF error");
#endif

	ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_CONFIG, ~SBI_SSE_ATTR_CONFIG_ONESHOT);
	report(ret == SBI_ERR_INVALID_PARAM, "Write invalid config error");

	if (sse_event_is_global(event_id)) {
		ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_PREFERRED_HART, 0xFFFFFFFFUL);
		report(ret == SBI_ERR_INVALID_PARAM, "Set invalid hart id error");
	} else {
		/* Set Hart on local event -> RO */
		ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_PREFERRED_HART, current_thread_info()->hartid);
		report(ret == SBI_ERR_BAD_RANGE, "Set hart id on local event error");
	}

	/* Attr_count == 0 */
	sret = sse_event_get_attr_raw(event_id, SBI_SSE_ATTR_STATUS, 0, (unsigned long) &value, 0);
	report(sret.error == SBI_ERR_INVALID_PARAM, "Read attribute attr_count == 0 error");

	sret = sse_event_set_attr_raw(event_id, SBI_SSE_ATTR_STATUS, 0, (unsigned long) &value, 0);
	report(sret.error == SBI_ERR_INVALID_PARAM, "Write attribute attr_count == 0 error");

	/* Invalid attribute id */
	ret = sse_event_get_attr(event_id, SBI_SSE_ATTR_INTERRUPTED_A7 + 1, &value);
	report(ret == SBI_ERR_BAD_RANGE, "Read invalid attribute error");
	ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_INTERRUPTED_A7 + 1, value);
	report(ret == SBI_ERR_BAD_RANGE, "Write invalid attribute error");

	/* Misaligned phys address */
	sret = sse_event_get_attr_raw(event_id, SBI_SSE_ATTR_STATUS, 1, ((unsigned long) &value | 0x1), 0);
	report(sret.error == SBI_ERR_INVALID_ADDRESS, "Read attribute with invalid address error");
	sret = sse_event_set_attr_raw(event_id, SBI_SSE_ATTR_STATUS, 1, ((unsigned long) &value | 0x1), 0);
	report(sret.error == SBI_ERR_INVALID_ADDRESS, "Write attribute with invalid address error");

	report_prefix_pop();
}

static void sse_test_register_error(unsigned long event_id)
{
	unsigned long ret;

	report_prefix_push("register");

	ret = sse_event_unregister(event_id);
	report(ret == SBI_ERR_INVALID_STATE, "SSE unregister non registered event");

	ret = sse_event_register_raw(event_id, (void *) 0x1, NULL);
	report(ret == SBI_ERR_INVALID_PARAM, "SSE register misaligned entry");

	ret = sse_event_register_raw(event_id, (void *) sse_entry, NULL);
	report(ret == SBI_SUCCESS, "SSE register ok");
	if (ret)
		goto done;

	ret = sse_event_register_raw(event_id, (void *) sse_entry, NULL);
	report(ret == SBI_ERR_INVALID_STATE, "SSE register twice failure");
	if (!ret)
		goto done;

	ret = sse_event_unregister(event_id);
	report(ret == SBI_SUCCESS, "SSE unregister ok");

done:
	report_prefix_pop();
}

struct sse_simple_test_arg {
	bool done;
	unsigned long event_id;
};

static void sse_simple_handler(void *data, struct pt_regs *regs, unsigned int hartid)
{
	struct sse_simple_test_arg *arg = data;
	int ret;
	const unsigned long regs_len = (SBI_SSE_ATTR_INTERRUPTED_A7 - SBI_SSE_ATTR_INTERRUPTED_A6) + 1;
	unsigned long interrupted_state[regs_len];

	if ((regs->status & SSTATUS_SPP) == 0)
		report_fail("Interrupted S-mode");

	if (hartid != current_thread_info()->hartid)
		report_fail("Hartid correctly passed");

	sse_check_state(arg->event_id, SBI_SSE_STATE_RUNNING);
	if (sse_event_pending(arg->event_id))
		report_fail("Event is not pending");

	/* Try to change HARTID/Priority while running */
	if (sse_event_is_global(arg->event_id)) {
		ret = sse_event_set_attr(arg->event_id, SBI_SSE_ATTR_PREFERRED_HART, current_thread_info()->hartid);
		report(ret == SBI_ERR_INVALID_STATE, "Set hart id while running error");
	}

	ret = sse_event_set_attr(arg->event_id, SBI_SSE_ATTR_PRIO, 0);
	report(ret == SBI_ERR_INVALID_STATE, "Set priority while running error");

	ret = sse_event_get_attrs(arg->event_id, SBI_SSE_ATTR_INTERRUPTED_A6, interrupted_state, regs_len);
	report(ret == SBI_SUCCESS, "Read interrupted context from SSE handler ok");
	if (interrupted_state[0] != SBI_EXT_SSE_INJECT)
		report_fail("Interrupted state a6 check ok");
	if (interrupted_state[1] != SBI_EXT_SSE)
		report_fail("Interrupted state a7 check ok");

	arg->done = true;
}

static void sse_test_inject_simple(unsigned long event_id)
{
	unsigned long ret;
	struct sse_handler_arg args;
	struct sse_simple_test_arg test_arg = {.event_id = event_id};

	args.handler = sse_simple_handler;
	args.handler_data = &test_arg;
	args.stack = sse_alloc_stack();

	report_prefix_push("simple");

	ret = sse_check_state(event_id, SBI_SSE_STATE_UNUSED);
	if (ret)
		goto done;

	ret = sse_event_register(event_id, &args);
	report(ret == SBI_SUCCESS, "SSE register no error");
	if (ret)
		goto done;

	ret = sse_check_state(event_id, SBI_SSE_STATE_REGISTERED);
	if (ret)
		goto done;

	/* Be sure global events are targeting the current hart */
	sse_global_event_set_current_hart(event_id);

	ret = sse_event_enable(event_id);
	report(ret == SBI_SUCCESS, "SSE enable no error");
	if (ret)
		goto done;

	ret = sse_check_state(event_id, SBI_SSE_STATE_ENABLED);
	if (ret)
		goto done;

	ret = sse_event_inject(event_id, current_thread_info()->hartid);
	report(ret == SBI_SUCCESS, "SSE injection no error");
	if (ret)
		goto done;

	report(test_arg.done == 1, "SSE event handled ok");
	test_arg.done = 0;

	/* Set as oneshot and verify it is disabled */
	ret = sse_event_disable(event_id);
	report(ret == 0, "Disable event ok");
	ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_CONFIG, SBI_SSE_ATTR_CONFIG_ONESHOT);
	report(ret == 0, "Set event attribute as ONESHOT");
	ret = sse_event_enable(event_id);
	report(ret == 0, "Enable event ok");

	ret = sse_event_inject(event_id, current_thread_info()->hartid);
	report(ret == SBI_SUCCESS, "SSE injection 2 no error");
	if (ret)
		goto done;

	report(test_arg.done == 1, "SSE event handled ok");
	test_arg.done = 0;

	ret = sse_check_state(event_id, SBI_SSE_STATE_REGISTERED);
	if (ret)
		goto done;

	/* Clear ONESHOT FLAG */
	sse_event_set_attr(event_id, SBI_SSE_ATTR_CONFIG, 0);

	ret = sse_event_unregister(event_id);
	report(ret == SBI_SUCCESS, "SSE unregister no error");
	if (ret)
		goto done;

	ret = sse_check_state(event_id, SBI_SSE_STATE_UNUSED);
	if (ret)
		goto done;

done:
	sse_free_stack(args.stack);
	report_prefix_pop();
}

struct sse_foreign_cpu_test_arg {
	bool done;
	unsigned int expected_cpu;
	unsigned long event_id;
};

static void sse_foreign_cpu_handler(void *data, struct pt_regs *regs, unsigned int hartid)
{
	struct sse_foreign_cpu_test_arg *arg = data;

	smp_rmb();
	if (arg->expected_cpu != current_thread_info()->cpu) {
		report_fail("Received event on CPU (%d), expected CPU (%d)", current_thread_info()->cpu, arg->expected_cpu);
	}
	arg->done = true;
	smp_wmb();
}

struct sse_local_per_cpu {
	struct sse_handler_arg args;
	unsigned long ret;
};

struct sse_local_data {
	unsigned long event_id;
	struct sse_local_per_cpu *cpu_args[NR_CPUS];
};

static void sse_register_enable_local(void *data)
{
	struct sse_local_data *local_data = data;
	struct sse_local_per_cpu *cpu_arg = local_data->cpu_args[current_thread_info()->cpu];

	cpu_arg->ret = sse_event_register(local_data->event_id, &cpu_arg->args);
	if (cpu_arg->ret)
		return;

	cpu_arg->ret = sse_event_enable(local_data->event_id);
}

static void sse_disable_unregister_local(void *data)
{
	struct sse_local_data *local_data = data;
	struct sse_local_per_cpu *cpu_arg = local_data->cpu_args[current_thread_info()->cpu];

	cpu_arg->ret = sse_event_disable(local_data->event_id);
	if (cpu_arg->ret)
		return;

	cpu_arg->ret = sse_event_unregister(local_data->event_id);
}

static void sse_test_inject_local(unsigned long event_id)
{
	int cpu;
	unsigned long ret;
	struct sse_local_data local_data;
	struct sse_local_per_cpu *cpu_arg;
	struct sse_foreign_cpu_test_arg test_arg = {.event_id = event_id};

	report_prefix_push("local_dispatch");
	local_data.event_id = event_id;

	for_each_online_cpu(cpu) {
		cpu_arg = calloc(1, sizeof(struct sse_handler_arg));

		cpu_arg->args.stack = sse_alloc_stack();
		cpu_arg->args.handler = sse_foreign_cpu_handler;
		cpu_arg->args.handler_data = &test_arg;
		local_data.cpu_args[cpu] = cpu_arg;
	}

	on_cpus(sse_register_enable_local, &local_data);
	for_each_online_cpu(cpu) {
		if (local_data.cpu_args[cpu]->ret)
			report_abort("CPU failed to register/enable SSE event");

		test_arg.expected_cpu = cpu;
		smp_wmb();
		ret = sse_event_inject(event_id, cpus[cpu].hartid);
		if (ret)
			report_abort("CPU failed to register/enable SSE event");

		while(!test_arg.done)
			smp_rmb();

		test_arg.done = false;
	}

	on_cpus(sse_disable_unregister_local, &local_data);
	for_each_online_cpu(cpu) {
		if (local_data.cpu_args[cpu]->ret)
			report_abort("CPU failed to disable/unregister SSE event");
	}

	for_each_online_cpu(cpu) {
		cpu_arg = local_data.cpu_args[cpu];

		sse_free_stack(cpu_arg->args.stack);
	}

	report_pass("local event dispartch on all CPUs");
	report_prefix_pop();

}

static void sse_test_inject_global(unsigned long event_id)
{
	unsigned long ret;
	unsigned int cpu;
	struct sse_handler_arg args;
	struct sse_foreign_cpu_test_arg test_arg = {.event_id = event_id};
	enum sbi_sse_state state;

	args.handler = sse_foreign_cpu_handler;
	args.handler_data = &test_arg;
	args.stack = sse_alloc_stack();

	report_prefix_push("global_dispatch");

	ret = sse_event_register(event_id, &args);
	if (ret)
		goto done;

	for_each_online_cpu(cpu) {
		test_arg.expected_cpu = cpu;
		smp_wmb();
		ret = sse_event_set_attr(event_id, SBI_SSE_ATTR_PREFERRED_HART, cpu);
		if (ret) {
			report_fail("Failed to set preferred hart");
			goto done;
		}

		ret = sse_event_enable(event_id);
		if (ret) {
			report_fail("Failed to enable SSE event");
			goto done;
		}

		ret = sse_event_inject(event_id, cpu);
		if (ret) {
			report_fail("Failed to inject event");
			goto done;
		}

		while(!test_arg.done)
			smp_rmb();

		test_arg.done = false;

		/* Wait for event to be in ENABLED state */
		do {
			ret = sse_get_state(event_id, &state);
			if (ret) {
				report_fail("Failed to get event state");
				goto done;
			}
		} while(state != SBI_SSE_STATE_ENABLED);

		ret = sse_event_disable(event_id);
		if (ret) {
			report_fail("Failed to disable SSE event");
			goto done;
		}

		report_pass("Global event on CPU %d", cpu);
	}

done:
	ret = sse_event_unregister(event_id);
	if (ret)
		report_fail("Failed to unregister event");

	sse_free_stack(args.stack);
	report_prefix_pop();
}

struct priority_test_arg {
	unsigned long evt;
	bool called;
	u32 prio;
	struct priority_test_arg *next_evt_arg;
	void (*check_func)(struct priority_test_arg *arg);
};

static void sse_hi_priority_test_handler(void *arg, struct pt_regs *regs,
					 unsigned int hartid)
{
	struct priority_test_arg *targ = arg;
	struct priority_test_arg *next = targ->next_evt_arg;

	targ->called = 1;
	if (next) {
		sse_event_inject(next->evt, current_thread_info()->hartid);
		if (sse_event_pending(next->evt))
			report_fail("Higher priority event is pending");
		if (!next->called)
			report_fail("Higher priority event was not handled");
	}
}

static void sse_low_priority_test_handler(void *arg, struct pt_regs *regs,
					  unsigned int hartid)
{
	struct priority_test_arg *targ = arg;
	struct priority_test_arg *next = targ->next_evt_arg;

	targ->called = 1;

	if (next) {
		sse_event_inject(next->evt, current_thread_info()->hartid);

		if (!sse_event_pending(next->evt))
			report_fail("Lower priority event is pending");

		if (next->called)
			report_fail("Lower priority event %s was handle before %s",
			      sse_evt_name(next->evt), sse_evt_name(targ->evt));
	}
}

static void sse_test_injection_priority_arg(struct priority_test_arg *args,
					    unsigned int args_size,
					    sse_handler_fn handler,
					    const char *test_name)
{
	unsigned int i;
	int ret;
	unsigned long event_id;
	struct priority_test_arg *arg;
	void *stack;
	struct sse_handler_arg event_args[args_size];
	struct sse_handler_arg *event_arg;

	report_prefix_push(test_name);

	for (i = 0; i < args_size; i++) {
		arg = &args[i];
		event_id = arg->evt;
		if (!sse_evt_can_inject(event_id))
			continue;

		stack = sse_alloc_stack();

		event_arg = &event_args[i];
		event_arg->handler = handler;
		event_arg->handler_data = (void *)arg;
		event_arg->stack = stack;

		if (i < (args_size - 1))
			arg->next_evt_arg = &args[i + 1];
		else
			arg->next_evt_arg = NULL;

		/* Be sure global events are targeting the current hart */
		sse_global_event_set_current_hart(event_id);

		sse_event_register(event_id, event_arg);
		sse_event_set_attr(event_id, SBI_SSE_ATTR_PRIO, arg->prio);
		sse_event_enable(event_id);
	}

	/* Inject first event */
	arg = &args[0];

	ret = sse_event_inject(arg->evt, current_thread_info()->hartid);
	report(ret == SBI_SUCCESS, "SSE injection no error");

	for (i = 0; i < args_size; i++) {
		arg = &args[i];
		event_id = arg->evt;

		if (!sse_evt_can_inject(event_id))
			continue;

		if (!arg->called)
			report_fail("Event %s handler called", sse_evt_name(arg->evt));

		sse_event_disable(event_id);
		sse_event_unregister(event_id);

		event_arg = &event_args[i];
		sse_free_stack(event_arg->stack);
	}

	report_prefix_pop();
}

static struct priority_test_arg hi_prio_args[] = {
	{.evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE},
	{.evt = SBI_SSE_EVENT_LOCAL_SOFTWARE},
	{.evt = SBI_SSE_EVENT_LOCAL_PMU},
	{.evt = SBI_SSE_EVENT_GLOBAL_RAS},
	{.evt = SBI_SSE_EVENT_LOCAL_RAS},
};

static struct priority_test_arg low_prio_args[] = {
	{.evt = SBI_SSE_EVENT_LOCAL_RAS},
	{.evt = SBI_SSE_EVENT_GLOBAL_RAS},
	{.evt = SBI_SSE_EVENT_LOCAL_PMU},
	{.evt = SBI_SSE_EVENT_LOCAL_SOFTWARE},
	{.evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE},
};

static struct priority_test_arg prio_args[] = {
	{.evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE, .prio = 5},
	{.evt = SBI_SSE_EVENT_LOCAL_SOFTWARE, .prio = 10},
	{.evt = SBI_SSE_EVENT_LOCAL_PMU, .prio = 15},
	{.evt = SBI_SSE_EVENT_GLOBAL_RAS, .prio = 20},
	{.evt = SBI_SSE_EVENT_LOCAL_RAS, .prio = 25},
};

static struct priority_test_arg same_prio_args[] = {
	{.evt = SBI_SSE_EVENT_LOCAL_PMU, .prio = 0},
	{.evt = SBI_SSE_EVENT_LOCAL_RAS, .prio = 10},
	{.evt = SBI_SSE_EVENT_LOCAL_SOFTWARE, .prio = 10},
	{.evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE, .prio = 10},
	{.evt = SBI_SSE_EVENT_GLOBAL_RAS, .prio = 20},
};

static void sse_test_injection_priority(void)
{
	report_prefix_push("prio");

	sse_test_injection_priority_arg(hi_prio_args, ARRAY_SIZE(hi_prio_args),
					sse_hi_priority_test_handler, "high");

	sse_test_injection_priority_arg(low_prio_args, ARRAY_SIZE(low_prio_args),
					sse_low_priority_test_handler, "low");

	sse_test_injection_priority_arg(prio_args, ARRAY_SIZE(prio_args),
					sse_low_priority_test_handler, "changed");

	sse_test_injection_priority_arg(same_prio_args, ARRAY_SIZE(same_prio_args),
					sse_low_priority_test_handler, "same_prio_args");

	report_prefix_pop();
}

static bool sse_can_inject(unsigned long event_id)
{
	int ret;
	unsigned long status;

	ret = sse_event_get_attr(event_id, SBI_SSE_ATTR_STATUS, &status);
	report(ret == 0, "SSE get attr status no error");
	if (ret)
		return 0;

	return !!(status & BIT(SBI_SSE_ATTR_STATUS_INJECT_OFFSET));
}

static void boot_secondary(void *data)
{
}

int main(int argc, char **argv)
{
	struct sbiret ret;
	unsigned long i, event;

	if (argc > 1 && !strcmp(argv[1], "-h")) {
		help();
		exit(0);
	}

	/*
	 * Dummy wakeup of all processors since some of them will be targetted
	 * by global events
	 */
	on_cpus(boot_secondary, NULL);
	report_prefix_push("sse");

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_SSE, 0, 0, 0, 0, 0);
	report(!ret.error, "SSE extension probing no error");
	if (ret.error)
		goto done;

	report(ret.value, "SSE extension is present");
	if (ret.value == 0)
		goto done;

	for (i = 0; i < ARRAY_SIZE(sse_event_infos); i++) {
		event = sse_event_infos[i].event_id;
		report_prefix_push(sse_event_infos[i].name);
		if (!sse_can_inject(event)) {
			sse_event_infos[i].can_inject = false;
			report_skip("Event does not support injection");
			report_prefix_pop();
			continue;
		}
		sse_test_attr(event);
		sse_test_register_error(event);
		sse_test_inject_simple(event);
		if (sse_event_is_global(event))
			sse_test_inject_global(event);
		else
			sse_test_inject_local(event);

		report_prefix_pop();
	}

	sse_test_injection_priority();

done:
	return report_summary();
}
