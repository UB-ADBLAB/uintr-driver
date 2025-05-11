#include "uitt_mapping.h"
#include "../uitt.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/* The hash table and its lock */
static DEFINE_HASHTABLE(uitt_pid_map, UITT_PID_BITS);
static DEFINE_SPINLOCK(uitt_pid_lock);

struct uintr_uitt *find_uitt_by_pid(pid_t pid) {
  struct uitt_mapping *mapping;
  struct uintr_uitt *uitt = NULL;
  unsigned long flags;

  spin_lock_irqsave(&uitt_pid_lock, flags);

  hash_for_each_possible(uitt_pid_map, mapping, node, (u32)pid) {
    if (mapping->pid == pid) {
      uitt = mapping->uitt;
      break;
    }
  }

  spin_unlock_irqrestore(&uitt_pid_lock, flags);
  return uitt;
}

int add_uitt_mapping(pid_t pid, struct uintr_uitt *uitt) {
  struct uitt_mapping *mapping;
  unsigned long flags;

  if (!uitt)
    return -EINVAL;

  mapping = kmalloc(sizeof(*mapping), GFP_KERNEL);
  if (!mapping)
    return -ENOMEM;

  mapping->pid = pid;
  mapping->uitt = uitt;

  spin_lock_irqsave(&uitt_pid_lock, flags);
  hash_add(uitt_pid_map, &mapping->node, (u32)pid);
  spin_unlock_irqrestore(&uitt_pid_lock, flags);

  return 0;
}

void remove_uitt_mapping(pid_t pid) {
  struct uitt_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;

  spin_lock_irqsave(&uitt_pid_lock, flags);

  hash_for_each_possible_safe(uitt_pid_map, mapping, tmp, node, (u32)pid) {
    if (mapping->pid == pid) {
      hash_del(&mapping->node);
      kfree(mapping);
      break;
    }
  }

  spin_unlock_irqrestore(&uitt_pid_lock, flags);
}

void remove_all_mappings_for_uitt(struct uintr_uitt *uitt) {
  struct uitt_mapping *mapping;
  struct hlist_node *tmp;
  unsigned long flags;
  unsigned int bkt;

  if (!uitt)
    return;

  spin_lock_irqsave(&uitt_pid_lock, flags);

  hash_for_each_safe(uitt_pid_map, bkt, tmp, mapping, node) {
    if (mapping->uitt == uitt) {
      hash_del(&mapping->node);
      kfree(mapping);
    }
  }

  spin_unlock_irqrestore(&uitt_pid_lock, flags);
}
