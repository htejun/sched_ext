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

struct {
	__uint(type, BPF_MAP_TYPE_RBTREE);
	__type(value, struct node_data);
} rbtree SEC(".maps");

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

// Key = just node_data.one
static int cmp2(const void *key, const struct rb_node *b)
{
	__u32 one;
	struct node_data *node_b;

	one = *(__u32 *)key;
	node_b = container_of(b, struct node_data, node);

	return node_b->one - one;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int check_rbtree(void *ctx)
{
	struct node_data *node, *found, *ret;
	struct node_data popped;
	struct node_data search;
	__u32 search2;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;

	node->one = calls;
	node->two = 6;
	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));

	ret = (struct node_data *)bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));

	bpf_rbtree_lock(bpf_rbtree_get_lock(&rbtree));

	search.one = calls;
	found = (struct node_data *)bpf_rbtree_find(&rbtree, &search, cmp);
	if (!found)
		goto unlock_ret;

	int node_ct = 0;
	struct node_data *iter = (struct node_data *)bpf_rbtree_first(&rbtree);

	while (iter) {
		node_ct++;
		iter = (struct node_data *)bpf_rbtree_next(&rbtree, iter);
	}

	ret = (struct node_data *)bpf_rbtree_remove(&rbtree, found);
	if (!ret)
		goto unlock_ret;

	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));

	bpf_rbtree_free_node(&rbtree, ret);

	__sync_fetch_and_add(&calls, 1);
	return 0;

unlock_ret:
	bpf_rbtree_unlock(bpf_rbtree_get_lock(&rbtree));
	return 0;
}

char _license[] SEC("license") = "GPL";
