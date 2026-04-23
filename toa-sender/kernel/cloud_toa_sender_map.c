#include "cloud_toa_sender_map.h"

#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/slab.h>

static u32 cloud_toa_sender_hash_key(u16 local_port)
{
	return jhash_1word((u32)local_port, 0);
}

static bool cloud_toa_sender_mapping_matches(const struct cloud_toa_sender_mapping *entry,
					     u16 local_port, u16 backend_family,
					     __be16 backend_port, const void *backend_addr)
{
	if (entry->local_port != local_port ||
	    entry->backend_family != backend_family ||
	    entry->backend_port != backend_port)
		return false;

	if (backend_family == AF_INET)
		return entry->backend_addr.addr4 == *(__be32 *)backend_addr;
	if (backend_family == AF_INET6)
		return !memcmp(&entry->backend_addr.addr6, backend_addr,
			       sizeof(entry->backend_addr.addr6));
	return false;
}

void cloud_toa_sender_table_init(struct cloud_toa_sender_table *table)
{
	hash_init(table->buckets);
	spin_lock_init(&table->lock);
}

void cloud_toa_sender_table_destroy(struct cloud_toa_sender_table *table)
{
	cloud_toa_sender_table_flush(table);
}

int cloud_toa_sender_table_add(struct cloud_toa_sender_table *table,
			       const struct cloud_toa_sender_mapping *mapping)
{
	struct cloud_toa_sender_mapping *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	*entry = *mapping;

	spin_lock_bh(&table->lock);
	hash_add(table->buckets, &entry->node,
		 cloud_toa_sender_hash_key(entry->local_port));
	spin_unlock_bh(&table->lock);
	return 0;
}

int cloud_toa_sender_table_del(struct cloud_toa_sender_table *table, u16 local_port)
{
	struct cloud_toa_sender_mapping *entry;

	spin_lock_bh(&table->lock);
	hash_for_each_possible(table->buckets, entry, node,
			       cloud_toa_sender_hash_key(local_port)) {
		if (entry->local_port != local_port)
			continue;
		hash_del(&entry->node);
		spin_unlock_bh(&table->lock);
		kfree(entry);
		return 0;
	}
	spin_unlock_bh(&table->lock);
	return -ENOENT;
}

struct cloud_toa_sender_mapping *
cloud_toa_sender_table_get(struct cloud_toa_sender_table *table, u16 local_port,
			   u16 backend_family, __be16 backend_port,
			   const void *backend_addr)
{
	struct cloud_toa_sender_mapping *entry;

	spin_lock_bh(&table->lock);
	hash_for_each_possible(table->buckets, entry, node,
			       cloud_toa_sender_hash_key(local_port)) {
		if (!cloud_toa_sender_mapping_matches(entry, local_port, backend_family,
							      backend_port, backend_addr))
			continue;
		spin_unlock_bh(&table->lock);
		return entry;
	}
	spin_unlock_bh(&table->lock);
	return NULL;
}

struct cloud_toa_sender_mapping *
cloud_toa_sender_table_get_by_local_port(struct cloud_toa_sender_table *table,
					 u16 local_port)
{
	struct cloud_toa_sender_mapping *entry;

	spin_lock_bh(&table->lock);
	hash_for_each_possible(table->buckets, entry, node,
			       cloud_toa_sender_hash_key(local_port)) {
		if (entry->local_port != local_port)
			continue;
		spin_unlock_bh(&table->lock);
		return entry;
	}
	spin_unlock_bh(&table->lock);
	return NULL;
}

void cloud_toa_sender_table_put(struct cloud_toa_sender_mapping *mapping)
{
}

void cloud_toa_sender_table_flush(struct cloud_toa_sender_table *table)
{
	struct cloud_toa_sender_mapping *entry;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&table->lock);
	hash_for_each_safe(table->buckets, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	spin_unlock_bh(&table->lock);
}
