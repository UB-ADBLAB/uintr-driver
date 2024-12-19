#ifndef _INTEL_UINTR_PROC_H
#define _INTEL_UINTR_PROC_H

#include <linux/types.h>
#include "protocol.h"
#include "uintr_types.h"

struct uintr_process_ctx *uintr_proc_create(struct task_struct *task);
int uintr_vector_create(struct uintr_process_ctx *proc, __u32 vector);
void uintr_proc_destroy(struct uintr_process_ctx *proc);
void uintr_vector_free(struct uintr_vector_ctx *vec);

#endif
