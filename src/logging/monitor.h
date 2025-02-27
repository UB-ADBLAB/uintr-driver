#ifndef _UINTR_MONITOR_H
#define _UINTR_MONITOR_H

#include "../uintr_types.h"
#include <linux/atomic.h>
#include <linux/kthread.h>

extern struct task_struct *monitor_task;
extern atomic_t monitor_should_exit;

int upid_monitor_thread(void *data);

int start_monitor_thread(struct uintr_process_ctx *proc);
void stop_monitor_thread(void);

#endif
