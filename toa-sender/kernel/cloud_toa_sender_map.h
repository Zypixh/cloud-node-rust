#ifndef _CLOUD_TOA_SENDER_MAP_H
#define _CLOUD_TOA_SENDER_MAP_H

#include <linux/hashtable.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct cloud_toa_sender_mapping {
	u16 local_port;
	u16 client_family;
	__be16 client_port;
	union {
		__be32 addr4;
		struct in6_addr addr6;
	} client_addr;
	u16 backend_family;
	__be16 backend_port;
	union {
		__be32 addr4;
		struct in6_addr addr6;
	} backend_addr;
	u64 created_at_ns;
	struct hlist_node node;
};

struct cloud_toa_sender_table {
	DECLARE_HASHTABLE(buckets, 8);
	spinlock_t lock;
};

void cloud_toa_sender_table_init(struct cloud_toa_sender_table *table);
void cloud_toa_sender_table_destroy(struct cloud_toa_sender_table *table);
int cloud_toa_sender_table_add(struct cloud_toa_sender_table *table,
			       const struct cloud_toa_sender_mapping *mapping);
int cloud_toa_sender_table_del(struct cloud_toa_sender_table *table, u16 local_port);
struct cloud_toa_sender_mapping *
cloud_toa_sender_table_get(struct cloud_toa_sender_table *table, u16 local_port,
			   u16 backend_family, __be16 backend_port,
			   const void *backend_addr);
struct cloud_toa_sender_mapping *
cloud_toa_sender_table_get_by_local_port(struct cloud_toa_sender_table *table,
					 u16 local_port);
void cloud_toa_sender_table_put(struct cloud_toa_sender_mapping *mapping);
void cloud_toa_sender_table_flush(struct cloud_toa_sender_table *table);

#endif
