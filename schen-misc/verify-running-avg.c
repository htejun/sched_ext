#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

typedef int32_t s32;
typedef uint32_t u32;
typedef unsigned long long u64;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef unsigned long long __u64;
#define U32_MAX UINT32_MAX
#define bpf_printk(fmt, args...)	printf(fmt"\n", ##args)
#define ARRAY_SIZE(ar)			(sizeof(ar) / sizeof(ar[0]))
const u64 slice_us = 20000;

#include "../samples/bpf/sched_ext_ravg.h"

static void verify_u64_x_u32_rshift(void)
{
	const u64 a = 0xfedcba987654ULL;
	const u32 b = 0xfebcba;
	const u32 shift = 16;
	const u64 expected = 0xfd9ae468acf103ULL;
	u64 res;

	res = u64_x_u32_rshift(a, b, shift);
	printf("(0x%llx*0x%x)>>%u=0x%llx, expected=0x%llx%s\n",
	       a, b, shift, res, expected, res != expected ? " ERROR" : "");
}

static void verify_ravg(u64 val)
{
	/*
	 * time 0      40      80      120     160     200     240     280    320
	 *      |-------|-------|-------|-------|-------|-------|-------|-------|
	 * run      [-----------------------]                   [-----------]
	 *              |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
	 * load*1024   256 448 640 736 832 880 672 504 336 252 168 382 596 703 554
	 */
	const u32 expected_dcyc_1024[] = {
		  0,   0, 256, 448,	/*   0ms -  60ms */
		640, 736, 832, 880,	/*  80ms - 140ms */
		672, 504, 336, 252,	/* 160ms - 220ms */
		168, 382, 596, 703,	/* 240ms - 300ms */
		554,			/* 320ms */
	};
	const u32 run_periods[][2] = {
		{  20, 140 },
		{ 240, 300 },
		{  -1,  -1 },
	};
	const u64 ms_to_ns = 1000000;
	const u64 period_ns = 2 * slice_us * 1000;
	struct ravg_data rd = {};
	int i, run_idx = 0;

	for (i = 0; i < ARRAY_SIZE(expected_dcyc_1024); i++) {
		u32 now = i * 20;
		u32 start = run_periods[run_idx][0];
		u32 stop = run_periods[run_idx][1];
		u64 dcyc;

		dcyc = ravg_read(&rd, now * ms_to_ns, period_ns);

		if (now == start) {
			ravg_accumulate(&rd, val, now * ms_to_ns, period_ns);
		} else if (now == stop) {
			ravg_accumulate(&rd, 0, now * ms_to_ns, period_ns);
			run_idx++;
		}

		dcyc = u64_x_u32_rshift(dcyc, 1024, RAVG_FRAC_BITS) / val;

		printf("now=%3ums duty_cycle=%3llu expected=%3u %s%s%s\n",
		       now, dcyc, expected_dcyc_1024[i],
		       dcyc != expected_dcyc_1024[i] ? " ERROR" : "",
		       now == start ? " START" : "",
		       now == stop ? " STOP" : "");
	}
}

int main(void)
{
	int i;

	printf("** Verifying u64_x_u32_rshift()\n");
	verify_u64_x_u32_rshift();

	for (i = 1; i <= RAVG_VAL_BITS; i++) {
		u64 v = (1LLU << i) - 1;

		printf("** Verifying ravg(0x%llx)\n", v);
		verify_ravg(v);
	}
	return 0;
}
