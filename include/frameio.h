#ifndef _FRAMEIO_H_
#define _FRAMEIO_H_

#define MAX_FRAMEIO_NAME 100

#include <jansson.h>
#include <stdint.h>
#include "fsl_qbman_base.h"

struct frameio;

#define FRAMEIO_FLAG_DONT_BLOCK 0x1

/* Receive a frame - returns number received */
typedef int (*frameio_input_cb)(struct frameio *frameio,
				struct qbman_swp *swp,
				int flags,
				struct dpaa2_fd *result);
/* Send a frame - returns number sent */
typedef int (*frameio_output_cb)(struct frameio *frameio,
				 struct qbman_swp *swp,
				  struct dpaa2_fd *frame);
typedef int (*frameio_enable_cb)(struct frameio *frameio);

struct frameio {
	char name[MAX_FRAMEIO_NAME];
	char type[MAX_FRAMEIO_NAME];
	frameio_input_cb input;
	frameio_output_cb output;
	frameio_enable_cb enable;

	struct frameio *next;
};

typedef struct frameio* (*frameio_constructor)(json_t* json);

void add_frameio_type(const char *type, frameio_constructor constructor);

struct frameio *find_frameio_by_name(const char *name);

int enable_frameios();

#endif
