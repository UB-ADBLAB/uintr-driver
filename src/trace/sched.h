#ifndef _UINTR_SCHED_H
#define _UINTR_SCHED_H

#include "../uintr_types.h"
#include <linux/types.h>

// Initialize the scheduler tracing subsystem
int uintr_sched_trace_init(void);

// Clean up the scheduler tracing subsystem
void uintr_sched_trace_cleanup(void);

// Register a process context to be monitored for CPU migrations
int uintr_sched_trace_register_proc(struct uintr_process_ctx *proc);

// Unregister a process context from migration monitoring
void uintr_sched_trace_unregister_proc(struct uintr_process_ctx *proc);

#endif
