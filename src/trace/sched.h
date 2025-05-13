#ifndef _UINTR_SCHED_H
#define _UINTR_SCHED_H

#include "../inteldef.h"
#include <linux/types.h>

// Initialize the scheduler tracing subsystem
int uintr_sched_trace_init(void);

// Clean up the scheduler tracing subsystem
void uintr_sched_trace_cleanup(void);

#endif
