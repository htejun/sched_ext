#ifndef __SCHED_EXT_COMMON_H
#define __SCHED_EXT_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>
#include <errno.h>

#warning "remove the following once bpf can handle 64bit enums"
#define SCX_SLICE_INF		0xffffffffffffffffLLU
#define	SCX_DQ_FLAG_BUILTIN	(1LLU << 63)
#define	SCX_DQ_FLAG_LOCAL_ON	(1LLU << 61)
#define	SCX_DQ_INVALID		(SCX_DQ_FLAG_BUILTIN | 0)
#define	SCX_DQ_GLOBAL		(SCX_DQ_FLAG_BUILTIN | 1)
#define	SCX_DQ_LOCAL		(SCX_DQ_FLAG_BUILTIN | 2)
#define	SCX_DQ_LOCAL_ON		(SCX_DQ_FLAG_BUILTIN | SCX_DQ_FLAG_LOCAL_ON)
#define SCX_ENQ_PREEMPT		(1LLU << 32)
#define SCX_ENQ_REENQ		(1LLU << 40)
#define SCX_ENQ_LAST		(1LLU << 41)
#define SCX_ENQ_SCD_LOCAL	(1LLU << 42)

extern s32 scx_bpf_create_dq(u64 dq_id, s32 node) __ksym;
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags) __ksym;
extern u32 scx_bpf_dispatch_nr_slots(void) __ksym;
extern s32 scx_bpf_dispatch(struct task_struct *p, u64 dq_id, u64 enq_flags) __ksym;
extern bool scx_bpf_consume(u64 dq_id) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
extern s32 scx_bpf_dq_nr_queued(u64 dq_id) __ksym;
extern bool scx_bpf_test_and_clear_cpu_idle(s32 cpu) __ksym;
extern s32 scx_bpf_pick_idle_cpu(const cpumask_t *cpus_allowed) __ksym;
extern bool scx_bpf_has_idle_cpus(void) __ksym;
extern s32 scx_bpf_destroy_dq(u64 dq_id) __ksym;
extern bool scx_bpf_task_running(const struct task_struct *p) __ksym;
extern s32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;
extern const struct cpumask *scx_bpf_task_cpumask(const struct task_struct *p) __ksym;
extern struct cgroup *scx_bpf_task_cgroup(const struct task_struct *p) __ksym;
extern struct task_struct *scx_bpf_find_task_by_pid(s32 pid) __ksym;
extern void scx_bpf_reenqueue_local(void) __ksym;

extern s32 scx_bpf_pick_idle_cpu_untyped(unsigned long cpus_allowed) __ksym;
extern bool scx_bpf_has_idle_cpus_among(const struct cpumask *cpus_allowed) __ksym;
extern bool scx_bpf_has_idle_cpus_among_untyped(unsigned long cpus_allowed) __ksym;
extern s32 scx_bpf_cpumask_test_cpu(s32 cpu, const struct cpumask *cpumask) __ksym;
extern s32 scx_bpf_cpumask_first(const struct cpumask *cpus_allowed) __ksym;
extern s32 scx_bpf_cpumask_first_untyped(unsigned long cpus_allowed) __ksym;
extern bool scx_bpf_cpumask_intersects(const struct cpumask *src1p, const struct cpumask *src2p) __ksym;

extern int extl_bpf_init(u32 le_data_size_req, u32 sq_data_size_req) __ksym;
extern int extl_bpf_enable(void) __ksym;
extern struct extl_sq *extl_bpf_create_sq(u64 id) __ksym;
extern void extl_bpf_set_task_sq(struct task_struct *p, struct extl_sq *sq) __ksym;
extern struct extl_sq *extl_bpf_task_sq(struct task_struct *p) __ksym;
extern struct extl_sq *extl_bpf_find_sq(u64 id) __ksym;
extern void extl_bpf_sq_lock(struct extl_sq *sq) __ksym;
extern void extl_bpf_sq_lock_by_task(struct task_struct *p) __ksym;
extern void extl_bpf_sq_unlock(void) __ksym;
extern void extl_bpf_sq_lock_double(struct extl_sq *sq0, struct extl_sq *sq1) __ksym;
extern void extl_bpf_sq_lock_double_by_task(struct task_struct *p, struct extl_sq *sq) __ksym;
extern void extl_bpf_sq_unlock_double(void) __ksym;
extern void extl_bpf_enqueue_task(struct task_struct *p, u64 key) __ksym;
extern bool extl_bpf_dequeue_task(struct task_struct *p) __ksym;
extern void extl_bpf_dispatch_dequeue(struct task_struct *p) __ksym;
extern struct task_struct *extl_bpf_sq_first_task(struct extl_sq *sq) __ksym;

#define PF_KTHREAD			0x00200000	/* I am a kernel thread */
#define PF_EXITING			0x00000004
#define CLOCK_MONOTONIC			1

#define BPF_STRUCT_OPS(name, args...) \
SEC("struct_ops/"#name) \
BPF_PROG(name, ##args)

/**
 * MEMBER_VPTR - Obtain the verified pointer to a struct or array member
 * @base: struct or array to index
 * @member: dereferenced member (e.g. ->field, [idx0][idx1], ...)
 *
 * The verifier often gets confused by the instruction sequence the compiler
 * generates for indexing struct fields or arrays. This macro forces the
 * compiler to generate a code sequence which first calculates the byte offset,
 * checks it against the struct or array size and add that byte offset to
 * generate the pointer to the member to help the verifier.
 *
 * Ideally, we want to abort if the calculated offset is out-of-bounds. However,
 * BPF currently doesn't support abort, so evaluate to NULL instead. The caller
 * must check for NULL and take appropriate action to appease the verifier. To
 * avoid confusing the verifier, it's best to check for NULL and dereference
 * immediately.
 *
 *	vptr = MEMBER_VPTR(my_array, [i][j]);
 *	if (!vptr)
 *		return error;
 *	*vptr = new_value;
 */
#define MEMBER_VPTR(base, member) (typeof(base member) *)({			\
	u64 __base = (u64)base;							\
	u64 __addr = (u64)&(base member) - __base;				\
	asm volatile (								\
		"if %0 <= %[max] goto +2\n"					\
		"%0 = 0\n"							\
		"goto +1\n"							\
		"%0 += %1\n"							\
		: "+r"(__addr)							\
		: "r"(__base),							\
		  [max]"i"(sizeof(base) - sizeof(base member)));		\
	__addr;									\
})

#endif	/* __SCHED_EXT_COMMON_H */
