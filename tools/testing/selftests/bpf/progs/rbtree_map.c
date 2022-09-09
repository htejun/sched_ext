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

long calls;
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
	struct bpf_spin_lock *lock;
	__u32 search2;

	node = bpf_rbtree_alloc_node(&rbtree, sizeof(struct node_data));
	if (!node)
		return 0;

	node->one = calls;
	node->two = 6;
	lock = &rbtree_lock;
	bpf_rbtree_lock(lock);

	ret = (struct node_data *)bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

	bpf_rbtree_unlock(lock);

	bpf_rbtree_lock(lock);

	search.one = calls;
	found = (struct node_data *)bpf_rbtree_find(&rbtree, &search, cmp);
	if (!found)
		goto unlock_ret;

	/*int node_ct = 0;
	struct node_data *iter = (struct node_data *)bpf_rbtree_first(&rbtree);

	while (iter) {
		node_ct++;
		iter = (struct node_data *)bpf_rbtree_next(&rbtree, iter);
	}*/

	ret = (struct node_data *)bpf_rbtree_remove(&rbtree, found);
	if (!ret)
		goto unlock_ret;

	bpf_rbtree_unlock(lock);

	bpf_rbtree_free_node(&rbtree, ret);

	__sync_fetch_and_add(&calls, 1);
	return 0;

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

int stash_calls;
int do_unstash;
struct node_data *empty_sentinel;
#define STASH_TEST_PID 1234

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__stash(void *ctx)
{
        struct node_data *node, *map_val;
        int pid = STASH_TEST_PID;

	if (do_unstash)
		return 0;

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
	node->one = stash_calls;

	bpf_rbtree_lock(&rbtree_lock);
	node = bpf_rbtree_node_xchg(&rbtree, map_val, node);
	if (node) {
		bpf_rbtree_free_node(&rbtree, node);
	}

	bpf_rbtree_unlock(&rbtree_lock);
	do_unstash = 1;
	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int rb_node__unstash(void *ctx)
{
	struct node_data *node = NULL, *map_val, *ret;
	int pid = STASH_TEST_PID;

	if (!do_unstash)
		return 0;

	map_val = bpf_map_lookup_elem(&hash_map, &pid);
	if (!map_val)
		return 0;

	bpf_rbtree_lock(&rbtree_lock);
	node = bpf_rbtree_node_xchg(&rbtree, map_val, node);
	if (!node)
		goto unlock_ret;
	if (node->one != stash_calls) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

	ret = (struct node_data *)bpf_rbtree_add(&rbtree, node, less);
	if (!ret) {
		bpf_rbtree_free_node(&rbtree, node);
		goto unlock_ret;
	}

	stash_calls++;
	do_unstash = 0;
unlock_ret:
	bpf_rbtree_unlock(&rbtree_lock);
	return 0;
}

char _license[] SEC("license") = "GPL";
