#include "uitt.h"
#include "core.h"
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

// Global UITT manager defined in core.h
extern struct uintr_uitt_manager *uitt_mgr;
extern u32 uintr_max_uitt_entries;
extern u64 uintr_uitt_base_addr;

int uitt_init(void) {
  size_t uitt_size;
  void *uitt_base;

  // For now use fixed size of 256 entries
  uintr_max_uitt_entries = 256;

  // Calculate size with 16-byte alignment for entries
  uitt_size = uintr_max_uitt_entries * sizeof(struct uintr_uitt_entry);

  // Allocate 4KB aligned memory for UITT
  uitt_base = kzalloc(uitt_size, GFP_KERNEL);
  if (!uitt_base)
    return -ENOMEM;

  // Store physical address for MSR
  uintr_uitt_base_addr = virt_to_phys(uitt_base);

  // Verify 4KB alignment
  if (uintr_uitt_base_addr & 0xFFF) {
    pr_err("UINTR: UITT base address is not 4KB aligned\n");
    kfree(uitt_base);
    return -EINVAL;
  }

  // Allocate manager structure
  uitt_mgr = kzalloc(sizeof(*uitt_mgr), GFP_KERNEL);
  if (!uitt_mgr) {
    kfree(uitt_base);
    return -ENOMEM;
  }

  // Initialize bitmap for tracking allocated entries
  uitt_mgr->allocated_vectors =
      kzalloc(BITS_TO_LONGS(uintr_max_uitt_entries) * sizeof(long), GFP_KERNEL);
  if (!uitt_mgr->allocated_vectors) {
    kfree(uitt_base);
    kfree(uitt_mgr);
    return -ENOMEM;
  }

  uitt_mgr->entries = uitt_base;
  spin_lock_init(&uitt_mgr->lock);

  pr_info("UINTR: UITT initialized at physical address 0x%llx\n",
          uintr_uitt_base_addr);
  return 0;
}

void uitt_cleanup(void) {
  if (!uitt_mgr)
    return;

  if (uitt_mgr->entries) {
    kfree(uitt_mgr->entries);
    uitt_mgr->entries = NULL;
  }

  if (uitt_mgr->allocated_vectors) {
    kfree(uitt_mgr->allocated_vectors);
    uitt_mgr->allocated_vectors = NULL;
  }

  kfree(uitt_mgr);
  uitt_mgr = NULL;
}

int uitt_alloc_entry(struct uintr_vector_ctx *vec) {
  unsigned long flags;
  int idx;

  if (!vec || !uitt_mgr || !uitt_mgr->entries || !vec->uitte)
    return -EINVAL;

  spin_lock_irqsave(&uitt_mgr->lock, flags);

  // Find first free entry
  idx =
      find_first_zero_bit(uitt_mgr->allocated_vectors, uintr_max_uitt_entries);
  if (idx >= uintr_max_uitt_entries) {
    spin_unlock_irqrestore(&uitt_mgr->lock, flags);
    return -ENOSPC;
  }

  // Mark entry as used
  set_bit(idx, uitt_mgr->allocated_vectors);

  // Program UITT entry
  uitt_mgr->entries[idx] = *vec->uitte;

  spin_unlock_irqrestore(&uitt_mgr->lock, flags);

  pr_debug("UINTR: Allocated UITT entry %d for vector %u\n", idx, vec->vector);
  return idx;
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
  memset(&uitt_mgr->entries[idx], 0, sizeof(struct uintr_uitt_entry));
  clear_bit(idx, uitt_mgr->allocated_vectors);

  spin_unlock_irqrestore(&uitt_mgr->lock, flags);

  pr_debug("UINTR: Freed UITT entry %u\n", idx);
  return 0;
}

u64 uitt_get_physical_addr(void) { return uintr_uitt_base_addr; }
