#ifndef _INTEL_UINTR_PROC_H
#define _INTEL_UINTR_PROC_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "protocol.h"

struct uintr_state;

struct uintr_process_ctx {
  struct task_struct *task;
  void *handler;
  struct uintr_state state;
  struct uintr_upid *upid;
  bool handler_active;
  spinlock_t ctx_lock;
  struct list_head vectors;
};

struct uintr_vector_ctx {
  struct list_head node;
  __u32 vector;
  struct uintr_uitt_entry *uitte;
  struct uintr_process_ctx *proc;
};

struct uintr_process_ctx *uintr_proc_create(struct task_struct *task);

int uintr_vector_create(struct uintr_process_ctx *proc, __u32 vector);
void uintr_proc_destroy(struct uintr_process_ctx *proc);
void uintr_vector_free(struct uintr_vector_ctx *vec);

#endif
