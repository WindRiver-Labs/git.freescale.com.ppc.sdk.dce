
#define NR_CPUS 8

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP { { 0, 0, 0, PTHREAD_MUTEX_ADAPTIVE_NP, { 0, 0, 0, 0 }, 0, { 0 }, 0, 0 } }


struct dpaa2_io {
	atomic_t refs;
	struct dpaa2_io_desc dpio_desc;
	struct qbman_swp_desc swp_desc;
	struct qbman_swp *swp;
	struct list_head node;

	/*
	 * As part of simplifying assumptions, we provide an
	 * irq-safe lock for each type of DPIO operation that
	 * isn't innately lockless. The selection algorithms
	 * (which are simplified) require this, whereas
	 * eventually adherence to cpu-affinity will presumably
	 * relax the locking requirements.
	 */
	pthread_mutex_t lock_mgmt_cmd;

	/* Protect the list of notifications */
	pthread_mutex_t lock_notifications;

	struct list_head notifications;
};

struct dpaa2_io_store {
        unsigned int max;
        dma_addr_t paddr;
        struct dpaa2_dq *vaddr;
        void *alloced_addr; /* unaligned value from kmalloc() */
        unsigned int idx; /* position of the next-to-be-returned entry */
        struct qbman_swp *swp; /* portal used to issue VDQCR */
        struct device *dev; /* device used for DMA mapping */
};

