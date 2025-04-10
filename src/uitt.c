#include "uitt.h"
#include "logging/monitor.h"
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

// TODO: come up with permanent solution
#define MAX_ENTRIES 256

struct uintr_uitt_manager *uitt_mgr = NULL;
extern u32 uintr_max_uitt_entries;
extern u64 uintr_uitt_base_addr;
static struct uintr_process_ctx *uitt_proc_contexts[MAX_ENTRIES];

struct uintr_process_ctx *uitt_get_proc_ctx(unsigned int idx) {
  if (idx >= MAX_ENTRIES)
    return NULL;
  return uitt_proc_contexts[idx];
}

void uitt_set_proc_ctx(unsigned int idx, struct uintr_process_ctx *proc) {
  if (idx < MAX_ENTRIES)
    uitt_proc_contexts[idx] = proc;
}

int uitt_init(void) {
  size_t uitt_size;
  void *uitt_base;
  struct uintr_uitt *uitt;

  uintr_max_uitt_entries = 64;
  uitt_size = uintr_max_uitt_entries * sizeof(struct uintr_uitt_entry);

  // allocate uitt management structure
  uitt_mgr = kzalloc(sizeof(*uitt_mgr), GFP_KERNEL);
  if (!uitt_mgr)
    return -ENOMEM;

  // allocate actual uitt structure
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

  uintr_dump_uitt_state("uitt_init");

  return 0;
}

void uitt_cleanup(void) {
  if (!uitt_mgr)
    return;

  if (uitt_mgr->uitt) {
    if (uitt_mgr->uitt->entries) {
      free_pages(
          (unsigned long)uitt_mgr->uitt->entries,
          get_order(uitt_mgr->uitt->size * sizeof(struct uintr_uitt_entry)));
      uitt_mgr->uitt->entries = NULL;
    }
    kfree(uitt_mgr->uitt);
  }

  kfree(uitt_mgr);
  uitt_mgr = NULL;
}

int uitt_alloc_entry(struct uintr_process_ctx *proc) {
  struct uintr_uitt_entry *entry;
  unsigned long flags;
  int vector;

  if (!proc || !uitt_mgr)
    return -EINVAL;

  spin_lock_irqsave(&uitt_mgr->lock, flags);

  // Find first free vector
  vector = find_first_zero_bit(uitt_mgr->allocated_idx, UINTR_MAX_UVEC_NR);
  if (vector >= UINTR_MAX_UVEC_NR) {
    spin_unlock_irqrestore(&uitt_mgr->lock, flags);
    return -ENOSPC;
  }

  entry = &uitt_mgr->uitt->entries[vector];
  entry->valid = 1;
  entry->user_vec = vector;
  entry->target_upid_addr = (u64)proc->upid;
  proc->uitt_idx = vector;

  set_bit(vector, uitt_mgr->allocated_idx);

  spin_unlock_irqrestore(&uitt_mgr->lock, flags);
  pr_info("UINTR: Allocated UITT entry %d for process %d\n", vector,
          proc->task->pid);

  uitt_set_proc_ctx(vector, proc);

  uintr_dump_uitt_entry_state(&uitt_mgr->uitt->entries[vector], vector,
                              "uitt_alloc");
  uintr_dump_upid_state(proc->upid, "uitt_alloc");
  return vector;
}

int uitt_free_entry(unsigned int idx) {
  unsigned long flags;

  if (!uitt_mgr || idx >= uintr_max_uitt_entries)
    return -EINVAL;

  spin_lock_irqsave(&uitt_mgr->lock, flags);

  if (!test_bit(idx, uitt_mgr->allocated_idx)) {
    spin_unlock_irqrestore(&uitt_mgr->lock, flags);
    return -EINVAL;
  }

  // Clear entry
  memset(&uitt_mgr->uitt->entries[idx], 0, sizeof(struct uintr_uitt_entry));
  clear_bit(idx, uitt_mgr->allocated_idx);

  spin_unlock_irqrestore(&uitt_mgr->lock, flags);

  uintr_dump_uitt_state("uitt_free_after");

  pr_info("UINTR: Freed UITT entry %u\n", idx);
  return 0;
}

void uintr_dump_uitt_entry_state(const struct uintr_uitt_entry *entry, int idx,
                                 const char *caller) {
  if (!entry) {
    pr_debug("UINTR [%s]: UITT entry %d is NULL\n", caller, idx);
    return;
  }

  pr_debug("UINTR [%s]: UITT Entry %d State:\n", caller, idx);
  pr_debug("  Raw memory (16 bytes):");
  print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1, entry,
                 sizeof(struct uintr_uitt_entry), true);

  pr_debug("  Valid: %u\n", entry->valid);
  pr_debug("  User Vector: 0x%x\n", entry->user_vec);
  pr_debug("  Target UPID Address: 0x%llx\n", entry->target_upid_addr);
}

void uintr_dump_uitt_state(const char *caller) {
  int i;

  if (!uitt_mgr || !uitt_mgr->uitt || !uitt_mgr->uitt->entries) {
    pr_debug("UINTR [%s]: UITT is not initialized\n", caller);
    return;
  }

  pr_debug("UINTR [%s]: UITT State Overview:\n", caller);
  pr_debug("  Base Address: 0x%llx\n", uintr_uitt_base_addr);
  pr_debug("  Max Entries: %u\n", uintr_max_uitt_entries);

  // Print allocated vectors
  pr_debug("  Allocated Vectors: ");
  for (i = 0; i < UINTR_MAX_UVEC_NR; i++) {
    if (test_bit(i, uitt_mgr->allocated_idx)) {
      pr_cont("%d ", i);
    }
  }
  pr_cont("\n");

  for (i = 0; i < UINTR_MAX_UVEC_NR; i++) {
    if (test_bit(i, uitt_mgr->allocated_idx)) {
      uintr_dump_uitt_entry_state(&uitt_mgr->uitt->entries[i], i, caller);
    }
  }
}
