// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <sys/syscall.h>
#include <test_progs.h>
#include "rbtree_map.skel.h"
#include "rbtree_map_fail.skel.h"
#include "rbtree_map_load_fail.skel.h"

static size_t log_buf_sz = 1048576; /* 1 MB */
static char obj_log_buf[1048576];

static struct {
	const char *prog_name;
	const char *expected_err_msg;
} rbtree_prog_load_fail_tests[] = {
	{"rb_node__field_store", "only read is supported"},
	{"rb_node__alloc_no_add", "Unreleased reference id=2 alloc_insn=3"},
	{"rb_node__two_alloc_one_add", "Unreleased reference id=2 alloc_insn=3"},
	{"rb_node__remove_no_free", "Unreleased reference id=6 alloc_insn=26"},
	{"rb_tree__add_wrong_type", "rbtree: R2 is of type task_struct but node_data is expected"},
	{"rb_tree__conditional_release_helper_usage",
		"R2 type=ptr_cond_rel_ expected=ptr_"},
};

void test_rbtree_map_load_fail(void)
{
	struct rbtree_map_load_fail *skel;

	skel = rbtree_map_load_fail__open_and_load();
	if (!ASSERT_ERR_PTR(skel, "rbtree_map_load_fail__open_and_load"))
		rbtree_map_load_fail__destroy(skel);
}

static void verify_fail(const char *prog_name, const char *expected_err_msg)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct rbtree_map_fail *skel;
	struct bpf_program *prog;
	int err;

	opts.kernel_log_buf = obj_log_buf;
	opts.kernel_log_size = log_buf_sz;
	opts.kernel_log_level = 1;

	skel = rbtree_map_fail__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "rbtree_map_fail__open_opts"))
		goto cleanup;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	bpf_program__set_autoload(prog, true);
	err = rbtree_map_fail__load(skel);
	if (!ASSERT_ERR(err, "unexpected load success"))
		goto cleanup;

	if (!ASSERT_OK_PTR(strstr(obj_log_buf, expected_err_msg), "expected_err_msg")) {
		fprintf(stderr, "Expected err_msg: %s\n", expected_err_msg);
		fprintf(stderr, "Verifier output: %s\n", obj_log_buf);
	}

cleanup:
	rbtree_map_fail__destroy(skel);
}

void test_rbtree_map_alloc_node__size_too_small(void)
{
	struct rbtree_map_fail *skel;
	struct bpf_program *prog;
	struct bpf_link *link;
	int err;

	skel = rbtree_map_fail__open();
	if (!ASSERT_OK_PTR(skel, "rbtree_map_fail__open"))
		goto cleanup;

	prog = skel->progs.alloc_node__size_too_small;
	bpf_program__set_autoload(prog, true);

	err = rbtree_map_fail__load(skel);
	if (!ASSERT_OK(err, "unexpected load fail"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.alloc_node__size_too_small);
	if (!ASSERT_OK_PTR(link, "link"))
		goto cleanup;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->size_too_small__alloc_fail, 1, "alloc_fail");

	bpf_link__destroy(link);
cleanup:
	rbtree_map_fail__destroy(skel);
}

void test_rbtree_map_add_node__no_lock(void)
{
	struct rbtree_map_fail *skel;
	struct bpf_program *prog;
	struct bpf_link *link;
	int err;

	skel = rbtree_map_fail__open();
	if (!ASSERT_OK_PTR(skel, "rbtree_map_fail__open"))
		goto cleanup;

	prog = skel->progs.add_node__no_lock;
	bpf_program__set_autoload(prog, true);

	err = rbtree_map_fail__load(skel);
	if (!ASSERT_OK(err, "unexpected load fail"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.add_node__no_lock);
	if (!ASSERT_OK_PTR(link, "link"))
		goto cleanup;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->no_lock_add__fail, 1, "alloc_fail");

	bpf_link__destroy(link);
cleanup:
	rbtree_map_fail__destroy(skel);
}

void test_rbtree_map_prog_load_fail(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rbtree_prog_load_fail_tests); i++) {
		if (!test__start_subtest(rbtree_prog_load_fail_tests[i].prog_name))
			continue;

		verify_fail(rbtree_prog_load_fail_tests[i].prog_name,
			    rbtree_prog_load_fail_tests[i].expected_err_msg);
	}
}

void test_rbtree_map(void)
{
	struct rbtree_map *skel;
	struct bpf_link *link;

	skel = rbtree_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rbtree_map__open_and_load"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.check_rbtree);
	if (!ASSERT_OK_PTR(link, "link"))
		goto cleanup;

	for (int i = 0; i < 100; i++)
		syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->calls, 100, "calls_equal");

	bpf_link__destroy(link);
cleanup:
	rbtree_map__destroy(skel);
}
