#include "proc_mapping.h"
#include "../common.h"
#include "../inteldef.h"
#include "../uitt.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/* Global hash table for unified process tracking */
static DEFINE_HASHTABLE(uintr_proc_hash, UINTR_PROC_BITS);
static DEFINE_SPINLOCK(uintr_proc_lock);

/* Function to find a process mapping by PID */
struct uintr_proc_mapping *find_proc_mapping(pid_t pid) {
  struct uintr_proc_mapping *mapping = NULL;
  unsigned long flags;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  hash_for_each_possible(uintr_proc_hash, mapping, node, pid) {
    if (mapping->pid == pid) {
      spin_unlock_irqrestore(&uintr_proc_lock, flags);
      return mapping;
    }
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
  return NULL;
}

/* Function to add or update a handler process mapping */
int add_proc_handler_mapping(pid_t pid, uintr_process_ctx *ctx) {
  struct uintr_proc_mapping *mapping;
  unsigned long flags;

  if (!ctx)
    return -EINVAL;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  /* Check if this process is already mapped */
  hash_for_each_possible(uintr_proc_hash, mapping, node, pid) {
    if (mapping->pid == pid) {
      /* Update the existing handler context */
      mapping->ctx = ctx;
      spin_unlock_irqrestore(&uintr_proc_lock, flags);
      return 0;
    }
  }

  /* Create a new mapping */
  mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
  if (!mapping) {
    spin_unlock_irqrestore(&uintr_proc_lock, flags);
    return -ENOMEM;
  }

  mapping->pid = pid;
  mapping->ctx = ctx;
  mapping->uitt = NULL; /* Not a sender yet */

  /* Add to hash table */
  hash_add(uintr_proc_hash, &mapping->node, pid);

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
  return 0;
}

/* Function to add or update a sender process mapping */
int add_proc_sender_mapping(pid_t pid, struct uintr_uitt *uitt) {
  struct uintr_proc_mapping *mapping;
  unsigned long flags;

  if (!uitt)
    return -EINVAL;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  /* Check if this process is already mapped */
  hash_for_each_possible(uintr_proc_hash, mapping, node, pid) {
    if (mapping->pid == pid) {
      /* Update the existing UITT */
      mapping->uitt = uitt;
      spin_unlock_irqrestore(&uintr_proc_lock, flags);
      return 0;
    }
  }

  /* Create a new mapping */
  mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
  if (!mapping) {
    spin_unlock_irqrestore(&uintr_proc_lock, flags);
    return -ENOMEM;
  }

  mapping->pid = pid;
  mapping->ctx = NULL; /* Not a handler yet */
  mapping->uitt = uitt;

  /* Add to hash table */
  hash_add(uintr_proc_hash, &mapping->node, pid);

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
  return 0;
}

/* Function to remove a process mapping by PID */
void remove_proc_mapping(pid_t pid) {
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

/* Function to clean up all mappings for a specific handler context */
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
      if (mapping->uitt) {
        /* Process is also a sender, just remove handler context */
        mapping->ctx = NULL;
      } else {
        /* Process is only a handler, remove the entire mapping */
        hash_del(&mapping->node);
        kfree(mapping);
      }
    }
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
}

/* Function to clean up all mappings for a specific UITT */
void remove_all_mappings_for_uitt(struct uintr_uitt *uitt) {
  struct uintr_proc_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;
  unsigned int bkt;

  if (!uitt)
    return;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  hash_for_each_safe(uintr_proc_hash, bkt, tmp, mapping, node) {
    if (mapping->uitt == uitt) {
      if (mapping->ctx) {
        /* Process is also a handler, just remove UITT */
        mapping->uitt = NULL;
        kfree(uitt->entries);
        kfree(uitt);
      } else {
        /* Process is only a sender, remove the entire mapping */
        hash_del(&mapping->node);
        kfree(mapping);
      }
    }
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);
}

/* Clean up the process mapping subsystem */
void proc_mapping_cleanup(void) {
  struct uintr_proc_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;
  unsigned int bkt;

  spin_lock_irqsave(&uintr_proc_lock, flags);

  /* Free all mappings */
  hash_for_each_safe(uintr_proc_hash, bkt, tmp, mapping, node) {
    hash_del(&mapping->node);
    kfree(mapping);
  }

  spin_unlock_irqrestore(&uintr_proc_lock, flags);

  pr_info("UINTR: Process mapping subsystem cleaned up\n");
}
