#ifndef _INTEL_UINTR_PROC_H
#define _INTEL_UINTR_PROC_H

#include "core.h"
#include "protocol.h"
#include "uintr_types.h"
#include <linux/types.h>

int uintr_alloc_vector(struct uintr_process_ctx *ctx,
                       struct uintr_vector_ctx *vec);

int uintr_vector_create(struct uintr_process_ctx *proc, __u32 vector);
void uintr_vector_free(struct uintr_vector_ctx *vec);

struct uintr_process_ctx *uintr_proc_create(struct task_struct *task,
                                            struct uintr_device *dev);
void uintr_proc_destroy(struct uintr_process_ctx *proc);

#endif
