#include "uitt.h"
#include "core.h"
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct uintr_uitt_manager *uitt_mgr = NULL;
extern u32 uintr_max_uitt_entries;
extern u64 uintr_uitt_base_addr;

int uitt_init(void) {
  size_t uitt_size;
  void *uitt_base;
  struct uintr_uitt *uitt;

  uintr_max_uitt_entries = 64;
  uitt_size = uintr_max_uitt_entries * sizeof(struct uintr_uitt_entry);

  uitt_mgr = kzalloc(sizeof(*uitt_mgr), GFP_KERNEL);
  if (!uitt_mgr)
    return -ENOMEM;

  uitt = kzalloc(sizeof(*uitt), GFP_KERNEL);
  if (!uitt) {
    kfree(uitt_mgr);
    return -ENOMEM;
  }

  // Allocate 4KB aligned memory for UITT entries using kmalloc
  // The page size is 4KB, so it should stay 4KB aligned
  uitt_base = (void *)__get_free_pages(GFP_KERNEL, get_order(uitt_size));
  if (!uitt_base) {
    kfree(uitt);
    kfree(uitt_mgr);
    return -ENOMEM;
  }

  // Clear memory
  memset(uitt_base, 0, uitt_size);

  uintr_uitt_base_addr = (u64)uitt_base;

  uitt->entries = uitt_base;
  uitt->size = uintr_max_uitt_entries;
  uitt_mgr->uitt = uitt;

  spin_lock_init(&uitt_mgr->lock);

  pr_info("UINTR: UITT initialized at virtual address 0x%llx\n",
          uintr_uitt_base_addr);
  pr_info("UINTR: UITT aligned to %lu bytes\n", PAGE_SIZE);

  return 0;
}

void uitt_cleanup(void) {
  if (!uitt_mgr)
    return;

  if (uitt_mgr->uitt->entries) {
    kfree(uitt_mgr->uitt->entries);
    uitt_mgr->uitt->entries = NULL;
  }

  if (uitt_mgr->allocated_vectors) {
    kfree(uitt_mgr->allocated_vectors);
  }

  kfree(uitt_mgr);
  uitt_mgr = NULL;
}

int uitt_alloc_entry(struct uintr_process_ctx *proc) {
  unsigned long flags;
  int vector;

  if (!proc || !uitt_mgr)
    return -EINVAL;

  spin_lock_irqsave(&uitt_mgr->lock, flags);

  // Find first free vector
  vector = find_first_zero_bit(uitt_mgr->allocated_vectors, UINTR_MAX_UVEC_NR);
  if (vector >= UINTR_MAX_UVEC_NR) {
    spin_unlock_irqrestore(&uitt_mgr->lock, flags);
    return -ENOSPC;
  }

  struct uintr_uitt_entry *entry = &uitt_mgr->uitt->entries[vector];
  entry->valid = 1;
  entry->user_vec = vector;
  entry->target_upid_addr = proc->upid; // virt_to_phys(proc->upid)?;

  set_bit(vector, uitt_mgr->allocated_vectors);

  spin_unlock_irqrestore(&uitt_mgr->lock, flags);
  pr_info("UINTR: Allocated UITT entry %d for process %d\n", vector,
          proc->task->pid);

  return vector;
}

int uitt_free_entry(unsigned int idx) {
  unsigned long flags;

  if (!uitt_mgr || idx >= uintr_max_uitt_entries)
    return -EINVAL;

  spin_lock_irqsave(&uitt_mgr->lock, flags);

  if (!test_bit(idx, uitt_mgr->allocated_vectors)) {
    spin_unlock_irqrestore(&uitt_mgr->lock, flags);
    return -EINVAL;
  }

  // Clear entry
  memset(&uitt_mgr->uitt->entries[idx], 0, sizeof(struct uintr_uitt_entry));
  clear_bit(idx, uitt_mgr->allocated_vectors);

  spin_unlock_irqrestore(&uitt_mgr->lock, flags);

  pr_info("UINTR: Freed UITT entry %u\n", idx);
  return 0;
}

u64 uitt_get_physical_addr(void) { return uintr_uitt_base_addr; }
