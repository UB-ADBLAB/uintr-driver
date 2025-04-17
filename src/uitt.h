#ifndef _INTEL_UINTR_UITT_H
#define _INTEL_UINTR_UITT_H

#include "inteldef.h"
#include <linux/types.h>

/* UITT configuration -- needs to be initialized during driver set up */
extern u32 uintr_max_uitt_entries;
extern u64 uintr_uitt_base_addr;

struct uintr_uitt_entry {
  u8 valid;
  u8 user_vec;
  u8 reserved[6];
  u64 target_upid_addr;
} __packed __aligned(16);

struct uintr_uitt {
  struct uintr_uitt_entry *entries;
  unsigned int size;
};

struct uintr_uitt_manager {
  struct uintr_uitt *uitt;
  DECLARE_BITMAP(allocated_idx, UINTR_MAX_UVEC_NR);
  spinlock_t lock;
};

struct uintr_process_ctx *uitt_get_proc_ctx(unsigned int idx);
void uitt_set_proc_ctx(unsigned int idx, struct uintr_process_ctx *proc);

int uitt_init(void);

void uitt_cleanup(void);

int uitt_alloc_entry(struct uintr_process_ctx *proc);

int uitt_free_entry(unsigned int idx);

// logging
void uintr_dump_uitt_entry_state(const struct uintr_uitt_entry *entry, int idx,
                                 const char *caller);

void uintr_dump_uitt_state(const char *caller);

#endif
