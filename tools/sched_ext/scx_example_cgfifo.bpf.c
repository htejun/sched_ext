// SPDX-License-Identifier: GPL-2.0
#include "scx_common.h"
#include "scx_example_cgfifo.h"

char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpus;
const volatile u64 cgrp_slice_ns = SCX_SLICE_DFL;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, CGF_NR_STATS);
} stats SEC(".maps");

static void stat_inc(enum cgf_stat_idx idx)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p)++;
}

struct cgf_cpu_ctx {
	u64			cur_cgid;
	u64			cur_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cgf_cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx SEC(".maps");

struct bpf_spin_lock tree_lock SEC(".bss.private");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct cgf_cgrp_ctx);
	__uint(max_entries, 16384);
} cgrp_ctx_hash SEC(".maps");

struct cgv_node {
	struct rb_node		rb_node;
	__u64			vtime;
	__u64			cgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RBTREE);
	__type(value, struct cgv_node);
	__array(lock, struct bpf_spin_lock);
} cgv_tree SEC(".maps") = {
	.lock = {
		[0] = &tree_lock,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct cgv_node *);
} cgv_node_hash SEC(".maps");

struct cgf_task_ctx {
	u64		bypassed_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgf_task_ctx);
} task_ctx SEC(".maps");

int exit_type = SCX_OPS_EXIT_NONE;
char exit_msg[SCX_OPS_EXIT_MSG_LEN];

u64 vtime_now;

/* gets inc'd on weight tree changes to expire the cached hweights */
unsigned long hweight_gen = 1;

static u64 div_round_up(u64 dividend, u64 divisor)
{
	return (dividend + divisor - 1) / divisor;
}

static bool time_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static bool cgv_node_less(struct rb_node *a, const struct rb_node *b)
{
	struct cgv_node *cgc_a, *cgc_b;

	cgc_a = container_of(a, struct cgv_node, rb_node);
	cgc_b = container_of(b, struct cgv_node, rb_node);

	return cgc_a->vtime < cgc_b->vtime;
}

static struct cgf_cpu_ctx *find_cpu_ctx(void)
{
	struct cgf_cpu_ctx *cpuc;
	u32 idx = 0;

	cpuc = bpf_map_lookup_elem(&cpu_ctx, &idx);
	if (!cpuc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return NULL;
	}
	return cpuc;
}

static struct cgf_cgrp_ctx *find_cgrp_ctx(u64 id)
{
	struct cgf_cgrp_ctx *cgc;

	cgc = bpf_map_lookup_elem(&cgrp_ctx_hash, &id);
	if (!cgc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return NULL;
	}
	return cgc;
}

static struct cgf_cgrp_ctx *find_ancestor_cgrp_ctx(struct cgroup *cgrp, int level)
{
	cgrp = bpf_get_ancestor_cgroup(cgrp, level);
	if (!cgrp) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return NULL;
	}

	return find_cgrp_ctx(bpf_get_cgroup_id(cgrp));
}

static int cgf_calc_hweight_loopfn(u32 idx, void *data)
{
	int level = idx;
	struct cgroup *origin = *(void **)data;
	struct cgf_cgrp_ctx *cgc;
	bool is_active;

	cgc = find_ancestor_cgrp_ctx(origin, level);
	if (!cgc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return 1;
	}

	if (!level) {
		cgc->hweight = CGF_HWEIGHT_ONE;
		cgc->hweight_gen = hweight_gen;
	} else {
		struct cgf_cgrp_ctx *pcgc;

		pcgc = find_ancestor_cgrp_ctx(origin, level - 1);
		if (!pcgc) {
			stat_inc(CGF_STAT_BAD_LOOKUP);
			return 1;
		}

		/*
		 * We can be oppotunistic here and not grab the tree_lock and
		 * deal with the occasional races. However, hweight updates are
		 * already cached and relatively low-frequency. Let's just do
		 * the straightforward thing.
		 */
		bpf_spin_lock(&tree_lock);
		is_active = cgc->nr_active;
		if (is_active) {
			cgc->hweight_gen = pcgc->hweight_gen;
			cgc->hweight = div_round_up(pcgc->hweight * cgc->weight,
						    pcgc->child_weight_sum);
		}
		bpf_spin_unlock(&tree_lock);

		if (!is_active) {
			stat_inc(CGF_STAT_HWT_RACE);
			return 1;
		}
	}

	return 0;
}

static void cgrp_refresh_hweight(struct cgroup *cgrp, struct cgf_cgrp_ctx *cgc)
{
	if (!cgc->nr_active) {
		stat_inc(CGF_STAT_HWT_SKIP);
		return;
	}

	if (cgc->hweight_gen == hweight_gen) {
		stat_inc(CGF_STAT_HWT_CACHE);
		return;
	}

	stat_inc(CGF_STAT_HWT_UPDATES);
	bpf_loop(cgrp->level + 1, cgf_calc_hweight_loopfn, &cgrp, 0);
}

static void cgrp_cap_budget(struct cgv_node *cgv_node, struct cgf_cgrp_ctx *cgc)
{
	u64 delta, vtime, max_budget;

	/*
	 * A node which is on the rbtree can't be pointed to from elsewhere yet
	 * and thus can't be updated and repositioned. Instead, we collect the
	 * vtime deltas separately and apply it asynchronously here.
	 */
	delta = cgc->vtime_delta;
	__sync_fetch_and_sub(&cgc->vtime_delta, delta);
	vtime = cgv_node->vtime + delta;

	/*
	 * Allow a cgroup to carry the maximum budget proportional to its
	 * hweight such that a full-hweight cgroup can immediately take up half
	 * of the CPUs at the most while staying at the front of the rbtree.
	 */
	max_budget = (cgrp_slice_ns * nr_cpus * cgc->hweight) /
		(2 * CGF_HWEIGHT_ONE);
	if (time_before(vtime, vtime_now - max_budget))
		vtime = vtime_now - max_budget;

	cgv_node->vtime = vtime;
}

static int cgrp_enqueued(struct cgroup *cgrp, struct cgf_cgrp_ctx *cgc)
{
	struct cgv_node *cgv_node_hash_val, *cgv_node = NULL;
	u64 id = bpf_get_cgroup_id(cgrp);
	int ret = 0;

	/* paired with cmpxchg in pick_next_cgroup_loopfn() */
	if (__sync_val_compare_and_swap(&cgc->queued, 0, 1)) {
		stat_inc(CGF_STAT_ENQ_SKIP);
		return 0;
	}

	cgv_node_hash_val = bpf_map_lookup_elem(&cgv_node_hash, &id);
	if (!cgv_node_hash_val)
		return -ENOENT;

	bpf_rbtree_lock(&tree_lock);

	/* NULL if the node is already on the rbtree */
	cgv_node = bpf_rbtree_node_xchg(&cgv_tree, cgv_node_hash_val, cgv_node);
	if (!cgv_node) {
		bpf_rbtree_unlock(&tree_lock);
		stat_inc(CGF_STAT_ENQ_RACE);
		return 0;
	}

	cgrp_cap_budget(cgv_node, cgc);

	if (!bpf_rbtree_add(&cgv_tree, cgv_node, cgv_node_less)) {
		bpf_rbtree_free_node(&cgv_tree, cgv_node);
		ret = -EINVAL;
	}

	bpf_rbtree_unlock(&tree_lock);
	return ret;
}

s64 BPF_STRUCT_OPS(cgf_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cgroup *cgrp = scx_bpf_task_cgroup(p);
	u64 cgid = bpf_get_cgroup_id(cgrp);
	struct cgf_task_ctx *taskc;
	struct cgf_cgrp_ctx *cgc;
	u32 idx = 0;
	int ret;

	p->scx.slice = SCX_SLICE_DFL;

	/*
	 * XXX - The following shouldn't fail but there is a bug in BPF
	 * which causes spurious lookup failures when it thinks
	 * operations are nested. For now, work around by dumping the
	 * task on the global dq.
	 */
	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return scx_bpf_dispatch(p, SCX_DQ_GLOBAL, enq_flags);
	}

	/*
	 * If select_cpu_dfl() is recommending local enqueue, the target CPU is
	 * idle. Follow it and charge the cgroup later in cgf_stopping() after
	 * the fact. Use the same mechanism to deal with tasks with custom
	 * affinities so that we don't have to worry about per-cgroup dq's
	 * containing tasks that can't be executed from some CPUs.
	 */
	if ((enq_flags & SCX_ENQ_SCD_LOCAL) || p->nr_cpus_allowed != nr_cpus) {
		/*
		 * Tell cgf_stopping() that this bypassed the regular scheduling
		 * path and should be force charged to the cgroup. 0 is used to
		 * indicate that the task isn't bypassing, so if the current
		 * runtime is 0, go back by one nanosecond.
		 */
		taskc->bypassed_at = p->se.sum_exec_runtime ?: (u64)-1;

		/*
		 * The global dq is deprioritized as we don't want to let tasks
		 * to boost themselves by constraining its cpumask. The
		 * deprioritization is rather severe, so let's not apply that to
		 * per-cpu kernel threads. This is ham-fisted. We probably wanna
		 * implement per-cgroup fallback dq's instead so that we have
		 * more control over when tasks with custom cpumask get issued.
		 */
		if ((enq_flags & SCX_ENQ_SCD_LOCAL) ||
		    (p->nr_cpus_allowed == 1 && (p->flags & PF_KTHREAD))) {
			stat_inc(CGF_STAT_LOCAL);
			return scx_bpf_dispatch(p, SCX_DQ_LOCAL, enq_flags);
		} else {
			stat_inc(CGF_STAT_GLOBAL);
			return scx_bpf_dispatch(p, SCX_DQ_GLOBAL, enq_flags);
		}
	} else {
		/*
		 * XXX - we shouldn't need this but ->stopping() may have
		 * skipped due to failed taskc lookup.
		 */
		taskc->bypassed_at = 0;
	}

	cgc = find_cgrp_ctx(cgid);
	if (!cgc)
		return -ENOENT;

	ret = scx_bpf_dispatch(p, cgid, enq_flags);
	if (ret)
		return ret;

	return cgrp_enqueued(cgrp, cgc);
}

void BPF_STRUCT_OPS(cgf_stopping, struct task_struct *p, bool runnable)
{
	struct cgf_task_ctx *taskc;
	struct cgroup *cgrp;
	struct cgf_cgrp_ctx *cgc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return;
	}

	if (!taskc->bypassed_at)
		return;

	cgrp = scx_bpf_task_cgroup(p);
	cgc = find_cgrp_ctx(bpf_get_cgroup_id(cgrp));
	if (!cgc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return;
	}

	__sync_fetch_and_add(&cgc->vtime_delta,
			p->se.sum_exec_runtime - taskc->bypassed_at);
	taskc->bypassed_at = 0;
}

struct cgf_update_active_weight_sums_loop_ctx {
	struct cgroup		*origin;	/* walking from this cgroup */
	bool			activate;	/* activate or deactivate? */
	bool			updated;	/* out param - hweight updated */
};

static int update_active_weight_sums_loopfn(u32 idx, void *data)
{
	struct cgf_update_active_weight_sums_loop_ctx *lctx = data;
	int level = lctx->origin->level - idx;
	struct cgf_cgrp_ctx *cgc, *pcgc = NULL;
	int lock_key = 0, ret;

	cgc = find_ancestor_cgrp_ctx(lctx->origin, level);
	if (!cgc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return 1;
	}
	if (level) {
		pcgc = find_ancestor_cgrp_ctx(lctx->origin, level - 1);
		if (!pcgc) {
			stat_inc(CGF_STAT_BAD_LOOKUP);
			return 1;
		}
	}

	/*
	 * We need the propagation protected by a lock to synchronize against
	 * weight changes. There's no reason to drop the lock at each level but
	 * bpf_spin_lock() doesn't want any function calls while locked.
	 */
	bpf_spin_lock(&tree_lock);

	ret = 1;
	if (lctx->activate) {
		if (!cgc->nr_active++) {
			lctx->updated = true;
			if (pcgc) {
				pcgc->child_weight_sum += cgc->weight;
				ret = 0;
			}
		}
	} else {
		if (!--cgc->nr_active) {
			lctx->updated = true;
			if (pcgc) {
				pcgc->child_weight_sum -= cgc->weight;
				ret = 0;
			}
		}
	}

	bpf_spin_unlock(&tree_lock);
	return ret;
}

/*
 * Walk the cgroup tree to update the active weight sums as tasks wake up and
 * sleep. The weight sums are used as the base when calculating the proportion a
 * given cgroup or task is entitled to at each level.
 */
static void update_active_weight_sums(struct cgroup *cgrp, bool runnable)
{
	struct cgf_update_active_weight_sums_loop_ctx loopc = {
		.origin = cgrp,
		.activate = runnable,
	};
	struct cgf_cgrp_ctx *cgc;

	cgc = find_cgrp_ctx(bpf_get_cgroup_id(cgrp));
	if (!cgc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return;
	}

	/*
	 * In most cases, a hot cgroup would have multiple threads going to
	 * sleep and waking up while the whole cgroup stays active. In leaf
	 * cgroups, ->nr_runnable which is updated with __sync operations gates
	 * ->nr_active updates, so that we don't have to grab the tree_lock
	 * repeatedly for a busy cgroup which is staying active.
	 */
	if (runnable) {
		if (__sync_fetch_and_add(&cgc->nr_runnable, 1))
			return;
		stat_inc(CGF_STAT_ACT);
	} else {
		if (__sync_sub_and_fetch(&cgc->nr_runnable, 1))
			return;
		stat_inc(CGF_STAT_DEACT);
	}

	/*
	 * If @cgrp is becoming runnable, its hweight should be refreshed after
	 * it's added to the weight tree so that enqueue has the up-to-date
	 * value. If @cgrp is becoming quiescent, the hweight should be
	 * refreshed before it's removed from the weight tree so that the usage
	 * charging which happens afterwards has access to the latest value.
	 */
	if (!runnable)
		cgrp_refresh_hweight(cgrp, cgc);

	/* propagate upwards */
	bpf_loop(cgrp->level, update_active_weight_sums_loopfn, &loopc, 0);
	if (loopc.updated)
		__sync_fetch_and_add(&hweight_gen, 1);

	if (runnable)
		cgrp_refresh_hweight(cgrp, cgc);
}

void BPF_STRUCT_OPS(cgf_runnable, struct task_struct *p, u64 enq_flags)
{
	update_active_weight_sums(scx_bpf_task_cgroup(p), true);
}

void BPF_STRUCT_OPS(cgf_quiescent, struct task_struct *p, u64 deq_flags)
{
	update_active_weight_sums(scx_bpf_task_cgroup(p), false);
}

void BPF_STRUCT_OPS(cgf_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgf_cgrp_ctx *cgc, *pcgc = NULL;
	int lock_key = 0;

	cgc = find_cgrp_ctx(bpf_get_cgroup_id(cgrp));
	if (!cgc)
		return;

	if (cgrp->level) {
		pcgc = find_ancestor_cgrp_ctx(cgrp, cgrp->level - 1);
		if (!pcgc)
			return;
	}

	bpf_spin_lock(&tree_lock);
	if (pcgc && cgc->nr_active)
		pcgc->child_weight_sum += (s64)weight - cgc->weight;
	cgc->weight = weight;
	bpf_spin_unlock(&tree_lock);
}

static int pick_next_cgroup_loopfn(u32 idx, void *data)
{
	struct cgv_node *cgv_node, *cgv_node_hash_val;
	struct cgf_cgrp_ctx *cgc;
	struct cgroup *cgrp;
	u32 hweight;
	u64 cgid;

	/* pop the front cgroup and wind vtime_now accordingly */
	bpf_rbtree_lock(&tree_lock);

	cgv_node = (void *)bpf_rbtree_first(&cgv_tree);
	if (!cgv_node) {
		bpf_rbtree_unlock(&tree_lock);
		stat_inc(CGF_STAT_PNC_NO_CGRP);
		return 1;
	}

	if (time_before(vtime_now, cgv_node->vtime))
		vtime_now = cgv_node->vtime;

	cgv_node = bpf_rbtree_remove(&cgv_tree, cgv_node);
	bpf_rbtree_unlock(&tree_lock);
	if (!cgv_node) {
		stat_inc(CGF_STAT_BAD_REMOVAL);
		return 0;
	}
	cgid = cgv_node->cgid;

	/*
	 * If lookup fails, the cgroup's gone. Free and move on. See
	 * cgf_cgroup_exit().
	 */
	cgrp = (struct cgroup *)bpf_get_cgroup_by_id(cgid);
	cgc = bpf_map_lookup_elem(&cgrp_ctx_hash, &cgid);
	if (!cgrp || !cgc) {
		stat_inc(CGF_STAT_PNC_GONE);
		goto out_free;
	}

	if (!scx_bpf_consume(cgid)) {
		stat_inc(CGF_STAT_PNC_EMPTY);
		goto out_stash;
	}

	/*
	 * Successfully consumed from the cgroup. This will be our current
	 * cgroup for the new slice. Refresh its hweight.
	 */
	cgrp_refresh_hweight(cgrp, cgc);

	/*
	 * As the cgroup may have more tasks, add it back to the rbtree. Note
	 * that here we charge the full slice upfront and then exact according
	 * to the actual consumption later. This prevents lowpri thundering herd
	 * from saturating the machine.
	 */
	bpf_rbtree_lock(&tree_lock);
	cgv_node->vtime += cgrp_slice_ns * CGF_HWEIGHT_ONE / (cgc->hweight ?: 1);
	cgrp_cap_budget(cgv_node, cgc);
	if (!bpf_rbtree_add(&cgv_tree, cgv_node, cgv_node_less))
		bpf_rbtree_free_node(&cgv_tree, cgv_node);
	bpf_rbtree_unlock(&tree_lock);
	*(u64 *)data = cgid;
	stat_inc(CGF_STAT_PNC_NEXT);
	return 1;

out_stash:
	cgv_node_hash_val = bpf_map_lookup_elem(&cgv_node_hash, &cgid);
	if (!cgv_node_hash_val) {
		stat_inc(CGF_STAT_PNC_GONE);
		goto out_free;
	}

	bpf_rbtree_lock(&tree_lock);

	/*
	 * Paired with cmpxchg in cgrp_enqueued(). If they see the following
	 * transition, they'll enqueue the cgroup. If they are earlier, we'll
	 * see their task in the dq below and requeue the cgroup.
	 */
	__sync_val_compare_and_swap(&cgc->queued, 1, 0);

	if (scx_bpf_dq_nr_queued(cgid)) {
		if (!bpf_rbtree_add(&cgv_tree, cgv_node, cgv_node_less))
			goto out_unlock_and_free;
	} else {
		cgv_node = bpf_rbtree_node_xchg(&cgv_tree, cgv_node_hash_val,
						cgv_node);
		if (cgv_node)
			goto out_unlock_and_free;
	}

	bpf_rbtree_unlock(&tree_lock);
	return 0;

out_unlock_and_free:
	bpf_rbtree_unlock(&tree_lock);
out_free:
	bpf_rbtree_free_node(&cgv_tree, cgv_node);
	return 0;
}

void BPF_STRUCT_OPS(cgf_consume, s32 cpu)
{
	struct cgf_cpu_ctx *cpuc;
	struct cgf_cgrp_ctx *cgc;
	struct cgroup *cgrp;
	u64 now = bpf_ktime_get_ns();
	u64 new_cgid;
	s64 delta;

	cpuc = find_cpu_ctx();
	if (!cpuc) {
		stat_inc(CGF_STAT_BAD_LOOKUP);
		return;
	}

	if (!cpuc->cur_cgid)
		goto pick_next_cgroup;

	if (time_before(now, cpuc->cur_at + cgrp_slice_ns)) {
		if (scx_bpf_consume(cpuc->cur_cgid)) {
			stat_inc(CGF_STAT_CNS_KEEP);
			return;
		}
		stat_inc(CGF_STAT_CNS_EMPTY);
	} else {
		stat_inc(CGF_STAT_CNS_EXPIRE);
	}

	/*
	 * The current cgroup is expiring. It was already charged a full slice.
	 * Calculate the actual usage and accumulate the delta.
	 */
	cgrp = (struct cgroup *)bpf_get_cgroup_by_id(cpuc->cur_cgid);
	cgc = bpf_map_lookup_elem(&cgrp_ctx_hash, &cpuc->cur_cgid);
	if (cgrp && cgc) {
		/*
		 * We want to update the vtime delta and then look for the next
		 * cgroup to execute but the latter needs to be done in a loop
		 * and we can't keep the lock held. Oh well...
		 */
		bpf_rbtree_lock(&tree_lock);
		__sync_fetch_and_add(&cgc->vtime_delta,
				     (cpuc->cur_at + cgrp_slice_ns - now) *
				     CGF_HWEIGHT_ONE / (cgc->hweight ?: 1));
		bpf_rbtree_unlock(&tree_lock);
	} else {
		stat_inc(CGF_STAT_CNS_GONE);
	}

pick_next_cgroup:
	cpuc->cur_at = now;

	if (scx_bpf_consume(SCX_DQ_GLOBAL)) {
		cpuc->cur_cgid = 0;
		return;
	}

	new_cgid = 0;
	bpf_loop(1 << 23, pick_next_cgroup_loopfn, &new_cgid, 0);
	cpuc->cur_cgid = new_cgid;
}

s32 BPF_STRUCT_OPS(cgf_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	struct cgf_task_ctx *taskc;

	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	taskc = bpf_task_storage_get(&task_ctx, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc)
		return -ENOMEM;

	taskc->bypassed_at = 0;
	return 0;
}

struct cgv_node *cgv_node_empty_sentinel;

int BPF_STRUCT_OPS(cgf_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	struct cgf_cgrp_ctx init_cgc = {
		.weight = args->weight,
		.hweight = CGF_HWEIGHT_ONE,
	};
	struct cgv_node *cgv_node, *cgv_node_hash_val;
	u64 cgid = bpf_get_cgroup_id(cgrp);
	int ret;

	/*
	 * Technically incorrect as cgroup ID is full 64bit while dq ID is
	 * 63bit. Should not be a problem in practice and easy to spot in the
	 * unlikely case that it breaks.
	 */
	ret = scx_bpf_create_dq(cgid, -1);
	if (ret)
		return ret;

	ret = bpf_map_update_elem(&cgrp_ctx_hash, &cgid, &init_cgc, BPF_ANY);
	if (ret)
		goto err_destroy_dq;

	ret = bpf_map_update_elem(&cgv_node_hash, &cgid, &cgv_node_empty_sentinel,
				  BPF_NOEXIST);
	if (ret)
		goto err_del_cgc;

	cgv_node_hash_val = bpf_map_lookup_elem(&cgv_node_hash, &cgid);
	if (!cgv_node_hash_val) {
		ret = -ENOENT;
		goto err_del_cgc;
	}

	cgv_node = bpf_rbtree_alloc_node(&cgv_tree, sizeof(struct cgv_node));
	if (!cgv_node) {
		ret = -ENOMEM;
		goto err_del_cgv_node;
	}

	cgv_node->cgid = cgid;
	cgv_node->vtime = vtime_now;

	bpf_rbtree_lock(&tree_lock);
	cgv_node = bpf_rbtree_node_xchg(&cgv_tree, cgv_node_hash_val, cgv_node);
	if (cgv_node)
		bpf_rbtree_free_node(&cgv_tree, cgv_node);
	bpf_rbtree_unlock(&tree_lock);

	return 0;

err_del_cgv_node:
	bpf_map_delete_elem(&cgv_node_hash, &cgid);
err_del_cgc:
	bpf_map_delete_elem(&cgrp_ctx_hash, &cgid);
err_destroy_dq:
	scx_bpf_destroy_dq(cgid);
	return ret;
}

void BPF_STRUCT_OPS(cgf_cgroup_exit, struct cgroup *cgrp)
{
	u64 id = bpf_get_cgroup_id(cgrp);

	/*
	 * For now, there's no way find and remove the cgv_node if it's on the
	 * cgv_tree. Let's drain them in the dispatch path as they get popped
	 * off the front of the tree.
	 */
	bpf_map_delete_elem(&cgv_node_hash, &id);
	bpf_map_delete_elem(&cgrp_ctx_hash, &id);
	scx_bpf_destroy_dq(id);
}


void BPF_STRUCT_OPS(cgf_exit, struct scx_ops_exit_info *ei)
{
	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_type = ei->type;
}

SEC(".struct_ops")
struct sched_ext_ops cgfifo_ops = {
	.enqueue		= (void *)cgf_enqueue,
	.consume		= (void *)cgf_consume,
	.runnable		= (void *)cgf_runnable,
	.stopping		= (void *)cgf_stopping,
	.quiescent		= (void *)cgf_quiescent,
	.prep_enable		= (void *)cgf_prep_enable,
	.cgroup_set_weight	= (void *)cgf_cgroup_set_weight,
	.cgroup_init		= (void *)cgf_cgroup_init,
	.cgroup_exit		= (void *)cgf_cgroup_exit,
	.exit			= (void *)cgf_exit,
	.flags			= SCX_OPS_CGROUP_KNOB_WEIGHT | SCX_OPS_ENQ_EXITING,
	.name			= "cgfifo",
};
