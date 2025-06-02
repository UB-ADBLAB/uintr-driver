#include "uitt.h"
#include "asm/paravirt.h"
#include "common.h"
#include "inteldef.h"
#include "logging/monitor.h"
#include "mappings/id_mapping.h"
#include "mappings/proc_mapping.h"
#include "msr.h"
#include "proc.h"
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

extern u32 uintr_max_uitt_entries;

int register_sender(uintr_receiver_id_t receiver_id, int vector) {
  uintr_process_ctx *receiver_ctx;
  uintr_process_ctx *sender_ctx;
  struct uintr_uitt *uitt = NULL;
  unsigned long flags;
  int ret;

  // Get the receiver context based off the receiver_id
  receiver_ctx = find_process_ctx_by_id(receiver_id);
  if (!receiver_ctx) {
    pr_err("UINTR: Failed to find CTX for receiver ID %llu\n", receiver_id);
    return -1;
  }

  if (!(receiver_ctx->role & UINTR_RECEIVER)) {
    pr_err("UINTR: Target context is not a receiver\n");
    return -EINVAL;
  }

  uintr_dump_upid_state(receiver_ctx->upid, "register_sender");

  // Find or create sender context
  sender_ctx = find_process_ctx(current->pid);
  if (!sender_ctx) {
    sender_ctx = uintr_create_ctx(current);
    if (!sender_ctx)
      return -ENOMEM;

    // Add to process mapping
    ret = add_process_mapping(current->pid, sender_ctx);
    if (ret < 0) {
      uintr_destroy_ctx(sender_ctx);
      return ret;
    }
  }

  spin_lock_irqsave(&sender_ctx->ctx_lock, flags);

  // Update role
  sender_ctx->role |= UINTR_SENDER;

  if (!sender_ctx->uitt) {
    // First time registering as sender, init the UITT
    uitt = uitt_init(current);
    if (!uitt) {
      spin_unlock_irqrestore(&sender_ctx->ctx_lock, flags);
      pr_err("UINTR: Failed to initialize UITT for PID %d\n", current->pid);
      if (sender_ctx->role == UINTR_SENDER) {
        // If this was the only role, remove the context
        remove_process_mapping(current->pid);
        uintr_destroy_ctx(sender_ctx);
      }
      return -ENOMEM;
    }
    sender_ctx->uitt = uitt;

    // Update state with UITT address
    sender_ctx->state.uitt_addr = (u64)uitt->entries | 1;
  } else {
    uitt = sender_ctx->uitt;
  }

  spin_unlock_irqrestore(&sender_ctx->ctx_lock, flags);

  // Create the entry which will be placed in the UITT
  struct uintr_uitt_entry entry = {
      .valid = 1,
      .user_vec = vector,
      .target_upid_addr = (u64)receiver_ctx->upid,
  };

  // Find the index to insert the entry
  int idx = uitt_find_empty_idx(uitt);
  if (idx < 0) {
    return -1;
  }

  // Insert the entry into the UITT
  uitt->entries[idx] = entry;

  dump_uintr_msrs(NULL);

  return idx;
}

int unregister_sender(int idx) {
  uintr_process_ctx *ctx;
  unsigned long flags;

  pr_debug("UINTR: Freeing ipi_idx %d for PID: %d\n", idx, current->pid);

  ctx = find_process_ctx(current->pid);
  if (!ctx) {
    pr_warn("UINTR: No context found for PID %d\n", current->pid);
    return -EINVAL;
  }

  if (!(ctx->role & UINTR_SENDER) || !ctx->uitt) {
    pr_warn("UINTR: Process is not a sender or has no UITT\n");
    return -EINVAL;
  }

  // Validate index
  if (idx < 0 || idx >= ctx->uitt->size) {
    pr_warn("UINTR: Invalid index %d (size: %u)\n", idx, ctx->uitt->size);
    return -EINVAL;
  }

  pr_debug(
      "UINTR: Entry[%d] before: valid=%u, vector=0x%x, target_upid=0x%llx\n",
      idx, ctx->uitt->entries[idx].valid, ctx->uitt->entries[idx].user_vec,
      ctx->uitt->entries[idx].target_upid_addr);

  // Mark the entry as invalid
  ctx->uitt->entries[idx].valid = 0;

  // Verify that we've actually cleared it
  pr_debug("UINTR: Entry[%d] after: valid=%u\n", idx,
           ctx->uitt->entries[idx].valid);

  // Ensure memory operations
  smp_wmb();

  // Check if this was the last entry
  if (is_uitt_empty(ctx->uitt)) {
    pr_debug("UINTR: All entries freed, cleaning up UITT for PID: %d\n",
             current->pid);

    spin_lock_irqsave(&ctx->ctx_lock, flags);

    // Free the UITT
    uitt_cleanup(ctx->uitt);
    ctx->uitt = NULL;

    // Update role
    ctx->role &= ~UINTR_SENDER;

    // Clear UITT MSR if this is the current process
    if (current->pid == ctx->task->pid) {
      wrmsrl(MSR_IA32_UINTR_TT, 0);
    }

    spin_unlock_irqrestore(&ctx->ctx_lock, flags);

    // If process has no more roles, clean up completely
    if (ctx->role == UINTR_NONE) {
      pr_debug("UINTR: Process has no more roles, cleaning up completely\n");
      remove_process_mapping(ctx->task->pid);
      uintr_destroy_ctx(ctx);
    }
  }

  return 0;
}

bool is_uitt_empty(struct uintr_uitt *uitt) {
  for (unsigned int i = 0; i < uitt->size; i++) {
    if (uitt->entries[i].valid == 1) {
      return false;
    }
  }
  return true;
}

uintr_receiver_id_t generate_receiver_id(uintr_process_ctx *ctx) {
  // TODO: add random bits + PID?
  uintr_receiver_id_t id = (uintr_receiver_id_t)ctx->task->pid;
  return id;
}

int uitt_find_empty_idx(struct uintr_uitt *uitt) {
  for (unsigned int i = 0; i < uitt->size; i++) {
    if (!uitt->entries[i].valid) {
      return i;
    }
  }
  return -1;
}

struct uintr_uitt *uitt_init(struct task_struct *task) {
  size_t uitt_size;
  struct uintr_uitt_entry *uitt_base;
  struct uintr_uitt *uitt;

  uintr_max_uitt_entries = 64;
  uitt_size = uintr_max_uitt_entries * sizeof(struct uintr_uitt_entry);

  // allocate actual uitt structure
  uitt = kzalloc(sizeof(*uitt), GFP_KERNEL);
  if (!uitt) {
    return ERR_PTR(ENOMEM);
  }

  // Allocate 4KB aligned memory for UITT entries using kmalloc
  // The page size is 4KB, so it should stay 4KB aligned
  uitt_base = (void *)__get_free_pages(GFP_KERNEL, get_order(uitt_size));
  if (!uitt_base) {
    kfree(uitt);
    return ERR_PTR(ENOMEM);
  }

  // Clear memory
  memset(uitt_base, 0, uitt_size);

  uitt->entries = uitt_base;
  uitt->size = uintr_max_uitt_entries;

  pr_debug("UINTR: UITT created for PID: %d at 0x%px\n", task->pid, uitt);
  pr_debug("UINTR: UITT aligned to %lu bytes\n", PAGE_SIZE);

  uintr_msr_set_misc(NULL);

  // Enable UITT
  wrmsrl(MSR_IA32_UINTR_TT, (u64)uitt->entries | 1);

  smp_wmb();

  return uitt;
}

void uitt_cleanup(struct uintr_uitt *uitt) {
  if (uitt) {
    if (uitt->entries) {
      free_pages((unsigned long)uitt->entries,
                 get_order(uitt->size * sizeof(struct uintr_uitt_entry)));
      uitt->entries = NULL;
    }
    kfree(uitt);
  }
}

void uintr_dump_uitt_entry_state(const struct uintr_uitt_entry *entry, int idx,
                                 const char *caller) {
  if (!entry) {
    pr_debug("UINTR [%s]: UITT entry %d is NULL\n", caller, idx);
    return;
  }

  pr_debug("UINTR [%s]: UITT Entry %d State:\n", caller, idx);
  pr_debug("  Raw memory (16 bytes):");
  print_hex_dump_debug("    ", DUMP_PREFIX_OFFSET, 16, 1, entry,
                       sizeof(struct uintr_uitt_entry), true);

  pr_debug("  Valid: %u\n", entry->valid);
  pr_debug("  User Vector: 0x%x\n", entry->user_vec);
  pr_debug("  Target UPID Address: 0x%llx\n", entry->target_upid_addr);
}
