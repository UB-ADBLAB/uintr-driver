#ifndef _INTEL_UINTR_PROC_H
#define _INTEL_UINTR_PROC_H

#include "driver.h"
#include "inteldef.h"
#include <linux/types.h>

uintr_process_ctx *uintr_create_ctx(struct task_struct *task);
void uintr_destroy_ctx(uintr_process_ctx *ctx);

#endif
