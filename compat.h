#define dma_addr_t uint64_t

#define container_of(p, type, member) \
	(type *)((unsigned char *)p - offsetof(type, member))

#define upper_32_bits(n) ((uint32_t)((n) >> 32))
#define lower_32_bits(n) ((uint32_t)((n) & 0xFFFFFFFF))

#define BUG_ON(c) assert(!(c))

#define BUG() assert(0);

#define pr_info(fmt, args...) printf(fmt, ##args)

#define pr_err(fmt, args...) do { \
	printf("ERROR: "); \
	printf(fmt, ##args); \
} while (0)

#define cpu_to_le32s(p) ({ \
	uint32_t *__p = p; \
	*__p = htobe32(*__p); \
})

#define le32_to_cpus(p) ({ \
	uint32_t *__p = p; \
	*__p = be32toh(*__p); \
})

/* Place holder until a real vfio setup is established */
#define vfio_alloc(s, a) malloc(s)
#define vfio_free free
