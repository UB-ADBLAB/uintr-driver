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
  unsigned int size;
  struct uintr_uitt_entry *entries;
};

int register_sender(uintr_receiver_id_t receiver_id, int vector);
int unregister_sender(int idx);

uintr_receiver_id_t generate_receiver_id(uintr_process_ctx *ctx);

int uitt_find_empty_idx(struct uintr_uitt *uitt);

struct uintr_uitt *uitt_init(struct task_struct *task);

void uitt_cleanup(struct uintr_uitt *uitt);

// logging
void uintr_dump_uitt_entry_state(const struct uintr_uitt_entry *entry, int idx,
                                 const char *caller);

bool is_uitt_empty(struct uintr_uitt *uitt);

#endif
