#include "proc_mapping.h"
#include "../common.h"
#include "../inteldef.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

// hash table for process tracking
static DEFINE_HASHTABLE(uintr_proc_hash, UINTR_PROC_BITS);
static DEFINE_SPINLOCK(uintr_proc_lock);

// finds a process context by PID
uintr_process_ctx *find_process_ctx(pid_t pid) {
  struct uintr_proc_mapping *mapping = NULL;
  uintr_process_ctx *ctx = NULL;
  unsigned long flags;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  hash_for_each_possible(uintr_proc_hash, mapping, node, pid) {
    if (mapping->pid == pid) {
      ctx = mapping->ctx;
      break;
    }
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
  return ctx;
}

// adds or updates a process mapping
int add_process_mapping(pid_t pid, uintr_process_ctx *ctx) {
  struct uintr_proc_mapping *mapping;
  unsigned long flags;

  if (!ctx)
    return -EINVAL;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  // Check if this process is already mapped
  hash_for_each_possible(uintr_proc_hash, mapping, node, pid) {
    if (mapping->pid == pid) {
      // Update the existing context
      mapping->ctx = ctx;
      spin_unlock_irqrestore(&uintr_proc_lock, flags);
      return 0;
    }
  }

  // Create a new mapping
  mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
  if (!mapping) {
    spin_unlock_irqrestore(&uintr_proc_lock, flags);
    return -ENOMEM;
  }

  mapping->pid = pid;
  mapping->ctx = ctx;

  // Add to hash table
  hash_add(uintr_proc_hash, &mapping->node, pid);

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
  return 0;
}

// removes a process mapping by PID
void remove_process_mapping(pid_t pid) {
  struct uintr_proc_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  hash_for_each_possible_safe(uintr_proc_hash, mapping, tmp, node, pid) {
    if (mapping->pid == pid) {
      hash_del(&mapping->node);
      kfree(mapping);
      break;
    }
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
}

// cleans up all mappings for a specific context
void remove_all_mappings_for_ctx(uintr_process_ctx *ctx) {
  struct uintr_proc_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;
  unsigned int bkt;

  if (!ctx)
    return;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  hash_for_each_safe(uintr_proc_hash, bkt, tmp, mapping, node) {
    if (mapping->ctx == ctx) {
      hash_del(&mapping->node);
      kfree(mapping);
    }
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
}

// cleans up the process mapping subsystem
void proc_mapping_cleanup(void) {
  struct uintr_proc_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;
  unsigned int bkt;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  // Free all mappings
  hash_for_each_safe(uintr_proc_hash, bkt, tmp, mapping, node) {
    hash_del(&mapping->node);
    kfree(mapping);
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);

  pr_info("UINTR: Process mapping subsystem cleaned up\n");
}
