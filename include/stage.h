#ifndef _STAGE_H_
#define _STAGE_H_

#define MAX_STAGE_NAME 100

#include <pthread.h>
#include <stdint.h>

#include "fsl_dpio.h"
#include "compat.h"
#include "fsl_qbman_base.h"
#include "fsl_qbman_portal.h"

struct action;
struct router;
struct frameio;


struct stage {
	char name[MAX_STAGE_NAME];
	struct action *action;
	struct router *router;
	struct frameio *input;
	struct frameio *output;

	cpu_set_t affinity_mask;

	int halt;
	struct stage *next;
	pthread_t threadid;

	uint16_t dpio_token;
	struct dpio_attr dpio_attr;
	struct qbman_swp* swp;


	/* Stats */
	uint64_t num_inputs;
	uint64_t num_outputs;
};

int init_stages(void);
int run_stages(void);
int halt_stages(void);

void print_stage_stats(struct stage *);

#endif
