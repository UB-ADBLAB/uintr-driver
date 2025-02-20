#ifndef _UINTR_MONITOR_H
#define _UINTR_MONITOR_H

#include "uintr_types.h"
#include <linux/atomic.h>
#include <linux/kthread.h>

extern struct task_struct *monitor_task;
extern atomic_t monitor_should_exit;

int upid_monitor_thread(void *data);

#endif
