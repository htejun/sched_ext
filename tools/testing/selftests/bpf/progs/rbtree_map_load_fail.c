// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct node_data_no_rb_node {
	__u64 one;
	__u64 two;
	__u64 three;
	__u64 four;
	__u64 five;
	__u64 six;
	__u64 seven;
};

struct bpf_spin_lock rbtree_lock SEC(".bss.private");

/* Should fail because value struct has no rb_node
 */
struct {
	__uint(type, BPF_MAP_TYPE_RBTREE);
	__type(value, struct node_data_no_rb_node);
	__array(lock, struct bpf_spin_lock);
} rbtree_fail_no_rb_node SEC(".maps") = {
	.lock = {
		[0] = &rbtree_lock,
	},
};

char _license[] SEC("license") = "GPL";
