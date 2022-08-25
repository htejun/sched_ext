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

	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));
	/* will never execute, alloc_node should fail */
	node->one = 1;
	ret = bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

unlock_ret:
	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));
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

	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));

	ret = bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

unlock_ret:
	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));
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

	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));

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
	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));
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

	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));

	ret = bpf_rbtree_add(&rbtree, task, less);
	/* Verifier should fail at bpf_rbtree_add, so don't bother handling
	 * failure.
	 */

	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));
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

	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));

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
	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));
	return 0;
}

char _license[] SEC("license") = "GPL";
