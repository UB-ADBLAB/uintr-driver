#include "id_mapping.h"
#include "../common.h"
#include "../inteldef.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

// The hash table and its lock
static DEFINE_HASHTABLE(receiver_id_map, RECEIVER_ID_BITS);
static DEFINE_SPINLOCK(receiver_id_lock);

// Function to find a context by ID
uintr_process_ctx *find_process_ctx_by_id(uintr_receiver_id_t id) {
  struct receiver_id_mapping *mapping;
  uintr_process_ctx *ctx = NULL;
  unsigned long flags;

  spin_lock_irqsave(&receiver_id_lock, flags);

  hash_for_each_possible(receiver_id_map, mapping, node, (u32)id) {
    if (mapping->id == id) {
      ctx = mapping->ctx;
      break;
    }
  }

  spin_unlock_irqrestore(&receiver_id_lock, flags);
  return ctx;
}

// Function to add a new mapping
int add_process_ctx_mapping(uintr_receiver_id_t id, uintr_process_ctx *ctx) {
  struct receiver_id_mapping *mapping;
  unsigned long flags;

  if (!ctx)
    return -EINVAL;

  mapping = kmalloc(sizeof(*mapping), GFP_KERNEL);
  if (!mapping)
    return -ENOMEM;

  mapping->id = id;
  mapping->ctx = ctx;

  spin_lock_irqsave(&receiver_id_lock, flags);
  hash_add(receiver_id_map, &mapping->node, (u32)id);
  spin_unlock_irqrestore(&receiver_id_lock, flags);

  return 0;
}

// Function to remove a mapping
void remove_process_ctx_mapping(uintr_receiver_id_t id) {
  struct receiver_id_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;

  spin_lock_irqsave(&receiver_id_lock, flags);

  hash_for_each_possible_safe(receiver_id_map, mapping, tmp, node, (u32)id) {
    if (mapping->id == id) {
      hash_del(&mapping->node);
      kfree(mapping);
      break;
    }
  }

  spin_unlock_irqrestore(&receiver_id_lock, flags);
}

// Function to clean up all mappings for a specific context
void remove_all_recid_mappings_for_ctx(uintr_process_ctx *ctx) {
  struct receiver_id_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;
  unsigned int bkt;

  if (!ctx)
    return;

  spin_lock_irqsave(&receiver_id_lock, flags);

  hash_for_each_safe(receiver_id_map, bkt, tmp, mapping, node) {
    if (mapping->ctx == ctx) {
      hash_del(&mapping->node);
      kfree(mapping);
    }
  }

  spin_unlock_irqrestore(&receiver_id_lock, flags);
}
