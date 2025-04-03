#ifndef _UINTR_TYPES_H
#define _UINTR_TYPES_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/* xstate structure - 48 byte total */
/* See Intel SDM 13.5.11 */
struct uintr_state {
  u64 handler;
  u64 stack_adjust;
  struct {
    u32 uitt_size;
    u8 uinv;
    u8 pad1;
    u8 pad2;
    union {
      struct {
        u8 uif : 1;
        u8 rsvd : 7;
      };
      u8 pad3;
    };
  } __packed misc;
  u64 upid_addr;
  u64 uirr;
  u64 uitt_addr;
} __packed;

struct uintr_vector_ctx {
  struct list_head node;
  __u32 vector;
  struct uintr_uitt_entry *uitte;
  struct uintr_process_ctx *proc;
};

struct uintr_process_ctx {
  struct task_struct *task;
  void *handler;
  int phys_core;
  struct uintr_state state;
  struct uintr_upid *upid;
  bool handler_active;
  int uitt_idx;
  spinlock_t ctx_lock;
};

#endif
