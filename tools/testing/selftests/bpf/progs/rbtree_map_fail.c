// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct node_data {
	struct rb_node node;
	__u32 one;
	__u32 two;
};

struct bpf_spin_lock rbtree_lock SEC(".bss.private");

struct {
	__uint(type, BPF_MAP_TYPE_RBTREE);
	__type(value, struct node_data);
	__array(lock, struct bpf_spin_lock);
} rbtree SEC(".maps") = {
	.lock = {
		[0] = &rbtree_lock,
	},
};

long calls;

static bool less(struct rb_node *a, const struct rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(a, struct node_data, node);
	node_b = container_of(b, struct node_data, node);

	return node_a->one < node_b->one;
}

// Key = node_datq
static int cmp(const void *key, const struct rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(key, struct node_data, node);
	node_b = container_of(b, struct node_data, node);

	return node_b->one - node_a->one;
}

long size_too_small__alloc_fail;

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int alloc_node__size_too_small(void *ctx)
{
	struct node_data *node, *ret;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(char));
	if (!node) {
		size_too_small__alloc_fail++;
		return 0;
	}

	bpf_rbtree_lock(&rbtree_lock);
	/* will never execute, alloc_node should fail */
	node->one = 1;
	ret = bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

unlock_ret:
	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

long no_lock_add__fail;

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int add_node__no_lock(void *ctx)
{
	struct node_data *node, *ret;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;

	node->one = 1;
	ret = bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		no_lock_add__fail++;
		/* will always execute, rbtree_add should fail
		 * because no lock held
		 */
		bpf_rbtree_free_node(&rbtree, node);
	}

unlock_ret:
	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__field_store(void *ctx)
{
	struct node_data *node;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;

	/* Only rbtree_map helpers can modify rb_node field */
	node->node.rb_left = NULL;
	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__alloc_no_add(void *ctx)
{
	struct node_data *node;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;
	/* The node alloc'd above is never added to the rbtree. It must be
	 * added or free'd before prog terminates.
	 */

	node->one = 42;
	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__two_alloc_one_add(void *ctx)
{
	struct node_data *node, *ret;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;
	node->one = 1;
	/* The node alloc'd above is never added to the rbtree. It must be
	 * added or free'd before prog terminates.
	 */

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;
	node->one = 42;

	bpf_rbtree_lock(&rbtree_lock);

	ret = bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

unlock_ret:
	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__remove_no_free(void *ctx)
{
	struct node_data *node, *ret;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;
	node->one = 42;

	bpf_rbtree_lock(&rbtree_lock);

	ret = bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

	ret = bpf_rbtree_remove(&rbtree, ret);
	if (!ret)
		goto unlock_ret;
	/* At this point we've successfully acquired a reference from
	 * bpf_rbtree_remove. It must be released via rbtree_add or
	 * rbtree_free_node before prog terminates.
	 */

unlock_ret:
	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_tree__add_wrong_type(void *ctx)
{
	/* Can't add a task_struct to rbtree
	 */
	struct task_struct *task;
	struct node_data *ret;

	task = bpf_get_current_task_btf();

	bpf_rbtree_lock(&rbtree_lock);

	ret = bpf_rbtree_add(&rbtree, task, less);
	/* Verifier should fail at bpf_rbtree_add, so don't bother handling
	 * failure.
	 */

	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_tree__conditional_release_helper_usage(void *ctx)
{
	struct node_data *node, *ret;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;
	node->one = 42;

	bpf_rbtree_lock(&rbtree_lock);

	ret = bpf_rbtree_add(&rbtree, node, less);
	/* Verifier should fail when trying to use CONDITIONAL_RELEASE
	 * type in a helper
	 */
	bpf_rbtree_free_node(&rbtree, node);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

unlock_ret:
	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

/* pid -> node_data lookup */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, struct node_data *);
} hash_map SEC(".maps");

struct node_data *empty_sentinel;
#define STASH_TEST_PID 1234

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__stash_no_check_xchg(void *ctx)
{
	struct node_data *node, *map_val;
	int pid = STASH_TEST_PID;

	map_val = bpf_map_lookup_elem(&hash_map, &pid);
	if (!map_val) {
		bpf_map_update_elem(&hash_map, &pid, &empty_sentinel, BPF_NOEXIST);
		map_val = bpf_map_lookup_elem(&hash_map, &pid);
		if (!map_val)
			return 0;
	}

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;
	node->one = 42;

	bpf_rbtree_lock(&rbtree_lock);
	node = bpf_rbtree_node_xchg(&rbtree, map_val, node);

	/* Here there should be a check:
	 * if (node) {
	 *        bpf_rbtree_free_node(&rbtree, node);
	 * }
	 * because the ptr xchg'd into node, if non-NULL, is a rbtree node
	 * that must be free'd or otherwise released
	 */

	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

char _license[] SEC("license") = "GPL";
