// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <bpf/bpf.h>
#include "scx_example_cgfifo.h"
#include "scx_example_cgfifo.skel.h"

#ifndef FILEID_KERNFS
#define FILEID_KERNFS		0xfe
#endif

static volatile int exit_req;

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

static float read_cpu_util(__u64 *last_sum, __u64 *last_idle)
{
	FILE *fp;
	char buf[4096];
	char *line, *cur = NULL, *tok;
	__u64 sum = 0, idle = 0;
	__u64 delta_sum, delta_idle;
	int idx;

	fp = fopen("/proc/stat", "r");
	if (!fp) {
		perror("fopen(\"/proc/stat\")");
		return 0.0;
	}

	if (!fgets(buf, sizeof(buf), fp)) {
		perror("fgets(\"/proc/stat\")");
		fclose(fp);
		return 0.0;
	}
	fclose(fp);

	line = buf;
	for (idx = 0; (tok = strtok_r(line, " \n", &cur)); idx++) {
		char *endp = NULL;
		__u64 v;

		if (idx == 0) {
			line = NULL;
			continue;
		}
		v = strtoull(tok, &endp, 0);
		if (!endp || *endp != '\0') {
			fprintf(stderr, "failed to parse %dth field of /proc/stat (\"%s\")\n",
				idx, tok);
			continue;
		}
		sum += v;
		if (idx == 4)
			idle = v;
	}

	delta_sum = sum - *last_sum;
	delta_idle = idle - *last_idle;
	*last_sum = sum;
	*last_idle = idle;

	return delta_sum ? (float)(delta_sum - delta_idle) / delta_sum : 0.0;
}

const char cgrp_mnt_point[] = "/sys/fs/cgroup";

struct fh_store {
	struct file_handle fh;
	char stor[MAX_HANDLE_SZ];
};

static void cgrp_id_to_path(uint64_t cgrp_id, int mnt_fd, char *path)
{
	struct fh_store fh_store;
	struct file_handle *fh = &fh_store.fh;
	char proc_path[PATH_MAX];
	int fd = -1;
	ssize_t ret;

	fh->handle_type = FILEID_KERNFS;
	fh->handle_bytes = sizeof(uint64_t);
	*(uint64_t *)fh->f_handle = cgrp_id;

	fd = open_by_handle_at(mnt_fd, fh, O_RDONLY);
	if (fd < 0) {
		snprintf(path, PATH_MAX, "open_by_handle_at: %s",
			 strerror(errno));
		goto out;
	}

	snprintf(proc_path, PATH_MAX, "/proc/self/fd/%d", fd);

	ret = readlink(proc_path, path, PATH_MAX);
	if (ret < 0) {
		snprintf(path, PATH_MAX, "read_link: %s", strerror(errno));
		goto out;
	}

	path[ret] = '\0';
	memmove(path, path + sizeof(cgrp_mnt_point) - 1,
		ret + 1 - (sizeof(cgrp_mnt_point) - 1));
	if (path[0] == '\0') {
		path[0] = '/';
		path[1] = '\0';
	}
out:
	if (fd >= 0)
		close(fd);
}

static void cgf_read_stats(struct scx_example_cgfifo *skel, __u64 *stats)
{
	__u64 cnts[CGF_NR_STATS][skel->rodata->nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * CGF_NR_STATS);

	for (idx = 0; idx < CGF_NR_STATS; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < skel->rodata->nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

struct cgrp_ctx_line_buf {
	char		path[PATH_MAX + 1];
	char		data[128];
};

static int cmp_lines(const void *p0, const void *p1)
{
	const struct cgrp_ctx_line_buf *l0 = *(void **)p0, *l1 = *(void **)p1;

	return strncmp(l0->path, l1->path, PATH_MAX);
}

static void cgf_dump_cgrp_ctx_hash(int map_fd)
{
#define CGRP_CTX_MAX_LINES 4096
	static struct cgrp_ctx_line_buf lines[CGRP_CTX_MAX_LINES];
	static struct cgrp_ctx_line_buf *ordered[CGRP_CTX_MAX_LINES];
	int cgrp_mnt_fd, i, nr_lines = 0;
	__u64 id;

	cgrp_mnt_fd = open(cgrp_mnt_point, O_RDONLY);
	assert(cgrp_mnt_fd >= 0);

	if (bpf_map_get_next_key(map_fd, NULL, &id))
		return;
	do {
		struct cgrp_ctx_line_buf *line = &lines[nr_lines++];
		struct cgf_cgrp_ctx cgc;
		char hweight_buf[16] = "    ";

		assert(!bpf_map_lookup_elem(map_fd, &id, &cgc));
		cgrp_id_to_path(id, cgrp_mnt_fd, line->path);
		if (cgc.nr_active)
			snprintf(hweight_buf, sizeof(hweight_buf) - 1, "%4.2f",
				 (float)cgc.hweight / CGF_HWEIGHT_ONE);
		snprintf(line->data, sizeof(line->data) - 1,
			 "%6llu run:act=%4u:%4u wt:hwt=%5u:%s cws:gen=%6lu:%6lu",
			 id, cgc.nr_runnable, cgc.nr_active, cgc.weight,
			 hweight_buf, cgc.child_weight_sum, cgc.hweight_gen);
	} while (nr_lines < CGRP_CTX_MAX_LINES &&
		 !bpf_map_get_next_key(map_fd, &id, &id));

	for (i = 0; i < nr_lines; i++)
		ordered[i] = &lines[i];

	qsort(ordered, nr_lines, sizeof(ordered[0]), cmp_lines);

	for (i = 0; i < nr_lines; i++)
		printf("%s %s\n", ordered[i]->data, ordered[i]->path);

	close(cgrp_mnt_fd);
}

int main(int argc, char **argv)
{
	struct scx_example_cgfifo *skel;
	struct bpf_link *link;
	struct timespec intv_ts = { .tv_sec = 2, .tv_nsec = 0 };
	bool dump_cgrps = false;
	__u64 last_cpu_sum = 0, last_cpu_idle = 0;
	__u64 last_stats[CGF_NR_STATS] = {};
	unsigned long seq = 0;
	s32 opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_example_cgfifo__open();
	if (!skel) {
		fprintf(stderr, "Failed to open: %s\n", strerror(errno));
		return 1;
	}

	skel->rodata->nr_cpus = libbpf_num_possible_cpus();

	while ((opt = getopt(argc, argv, "s:i:d")) != -1) {
		double v;

		switch (opt) {
		case 's':
			v = strtod(optarg, NULL);
			skel->rodata->cgrp_slice_ns = v * 1000000;
			break;
		case 'i':
			v = strtod(optarg, NULL);
			intv_ts.tv_sec = v;
			intv_ts.tv_nsec = (v - (float)intv_ts.tv_sec) * 1000000000;
			break;
		case 'd':
			dump_cgrps = true;
			break;
		case 'h':
		default:
			fprintf(stderr, "usage: %s [-s slice_ms] [-i interval_s] [-d]\n", argv[0]);
			return opt != 'h';
		}
	}

	printf("slice=%.1lfms intv=%.1lfs dump_cgrps=%d",
	       (double)skel->rodata->cgrp_slice_ns / 1000000.0,
	       (double)intv_ts.tv_sec + (double)intv_ts.tv_nsec / 1000000000.0,
	       dump_cgrps);

	if (scx_example_cgfifo__load(skel)) {
		fprintf(stderr, "Failed to load: %s\n", strerror(errno));
		return 1;
	}

	link = bpf_map__attach_struct_ops(skel->maps.cgfifo_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach_struct_ops: %s\n",
			strerror(errno));
		return 1;
	}

	while (!exit_req && !skel->bss->exit_type) {
		__u64 acc_stats[CGF_NR_STATS];
		__u64 stats[CGF_NR_STATS];
		float cpu_util;
		int i;

		cpu_util = read_cpu_util(&last_cpu_sum, &last_cpu_idle);

		cgf_read_stats(skel, acc_stats);
		for (i = 0; i < CGF_NR_STATS; i++)
			stats[i] = acc_stats[i] - last_stats[i];

		memcpy(last_stats, acc_stats, sizeof(acc_stats));

		printf("\n[SEQ %6lu cpu=%5.1lf hweight_gen=%lu]\n",
		       seq++, cpu_util * 100.0, skel->data->hweight_gen);
		printf("       act:%6llu  deact:%6llu local:%6llu global:%6llu\n",
		       stats[CGF_STAT_ACT],
		       stats[CGF_STAT_DEACT],
		       stats[CGF_STAT_LOCAL],
		       stats[CGF_STAT_GLOBAL]);
		printf("HWT   skip:%6llu   race:%6llu cache:%6llu update:%6llu\n",
		       stats[CGF_STAT_HWT_SKIP],
		       stats[CGF_STAT_HWT_RACE],
		       stats[CGF_STAT_HWT_CACHE],
		       stats[CGF_STAT_HWT_UPDATES]);
		printf("ENQ   skip:%6llu   race:%6llu\n",
		       stats[CGF_STAT_ENQ_SKIP],
		       stats[CGF_STAT_ENQ_RACE]);
		printf("CNS   keep:%6llu expire:%6llu empty:%6llu   gone:%6llu\n",
		       stats[CGF_STAT_CNS_KEEP],
		       stats[CGF_STAT_CNS_EXPIRE],
		       stats[CGF_STAT_CNS_EMPTY],
		       stats[CGF_STAT_CNS_GONE]);
		printf("PNC nocgrp:%6llu   next:%6llu empty:%6llu   gone:%6llu\n",
		       stats[CGF_STAT_PNC_NO_CGRP],
		       stats[CGF_STAT_PNC_NEXT],
		       stats[CGF_STAT_PNC_EMPTY],
		       stats[CGF_STAT_PNC_GONE]);
		printf("BAD lookup:%6llu remove:%6llu\n",
		       acc_stats[CGF_STAT_BAD_LOOKUP],
		       acc_stats[CGF_STAT_BAD_REMOVAL]);

		if (dump_cgrps)
			cgf_dump_cgrp_ctx_hash(bpf_map__fd(skel->maps.cgrp_ctx_hash));

		nanosleep(&intv_ts, NULL);
	}

	if (skel->bss->exit_type)
		fprintf(stderr, "exit_type=%d msg=\"%s\"\n",
			skel->bss->exit_type, skel->bss->exit_msg);

	bpf_link__destroy(link);
	scx_example_cgfifo__destroy(skel);

	return 0;
}
