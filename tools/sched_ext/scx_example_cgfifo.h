#ifndef __SCX_EXAMPLE_CGFIFO_H
#define __SCX_EXAMPLE_CGFIFO_H

enum {
	CGF_HWEIGHT_ONE		= 1LLU << 16,
};

enum cgf_stat_idx {
	CGF_STAT_ACT,
	CGF_STAT_DEACT,
	CGF_STAT_LOCAL,
	CGF_STAT_GLOBAL,

	CGF_STAT_HWT_UPDATES,
	CGF_STAT_HWT_CACHE,
	CGF_STAT_HWT_SKIP,
	CGF_STAT_HWT_RACE,

	CGF_STAT_ENQ_SKIP,
	CGF_STAT_ENQ_RACE,

	CGF_STAT_CNS_KEEP,
	CGF_STAT_CNS_EXPIRE,
	CGF_STAT_CNS_EMPTY,
	CGF_STAT_CNS_GONE,

	CGF_STAT_PNC_NO_CGRP,
	CGF_STAT_PNC_NEXT,
	CGF_STAT_PNC_EMPTY,
	CGF_STAT_PNC_GONE,
 
	CGF_STAT_BAD_LOOKUP,
	CGF_STAT_BAD_REMOVAL,

	CGF_NR_STATS,
};

struct cgf_cgrp_ctx {
	u32			nr_active;
	u32			nr_runnable;
	u32			queued;
	u32			weight;
	u32			hweight;
	u64			child_weight_sum;
	u64			hweight_gen;
	s64			vtime_delta;
};

#endif /* __SCX_EXAMPLE_CGFIFO_H */
