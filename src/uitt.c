#include "uitt.h"
#include "asm/paravirt.h"
#include "common.h"
#include "irq.h"
#include "logging/monitor.h"
#include "mappings/id_mapping.h"
#include "mappings/uitt_mapping.h"
#include "msr.h"
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

extern u32 uintr_max_uitt_entries;

// TODO: this is a bad way to do this, but the easiest to implement for now.
int unregister_sender(int idx) {
  u64 uitt_addr;
  rdmsrl(MSR_IA32_UINTR_TT, uitt_addr);
  struct uintr_uitt *uitt = (struct uintr_uitt *)uitt_addr;
  if (!uitt) {
    return -1;
    pr_warn("UINTR: UITT msr value missing.\n");
  }
  uitt->entries[idx].valid = 0;
  return 0;
}

int register_sender(uintr_receiver_id_t receiver_id, int vector) {
  uintr_process_ctx *ctx;

  // get the process context based off the receiver_id
  // we need the ctx to find the upid address which is required in the
  // uitt_entry we are about to create
  ctx = find_process_ctx_by_id(receiver_id);

  if (!ctx) {
    pr_err("UINTR: Failed to find CTX for receiver ID %llu\n", receiver_id);
    return -1;
  }

  uintr_dump_upid_state(ctx->upid, "register_sender");

  // must look up the target uitt where we are placing the entry
  struct uintr_uitt *uitt = find_uitt_by_pid(current->pid);

  // if it doesn't exist, it means this is the first time we are registering a
  // sender from this task, meaning we must init the uitt before adding the
  // entry.
  if (!uitt) {
    uitt = uitt_init(current);
  }

  // create the entry which will be placed in the uitt
  struct uintr_uitt_entry entry = {
      .valid = 1,
      .user_vec = vector,
      .target_upid_addr = (u64)ctx->upid,
  };

  // find the index to insert the entry
  int idx = uitt_find_empty_idx(uitt);

  if (idx < 0) {
    return -1;
  }

  // insert the entry into the uitt
  uitt->entries[idx] = entry;

  dump_uintr_msrs(NULL);

  return idx;
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

// could also accept PID?
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

  pr_info("UINTR: UITT created for PID: %d at 0x%px\n", task->pid, uitt);
  pr_info("UINTR: UITT aligned to %lu bytes\n", PAGE_SIZE);

  // TODO: should this be included in the state some how?
  add_uitt_mapping(task->pid, uitt);

  wrmsrl(MSR_IA32_UINTR_TT, (u64)uitt->entries | 1);

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
