#ifndef _UINTR_MONITOR_H
#define _UINTR_MONITOR_H

#include "../inteldef.h"
#include <linux/atomic.h>
#include <linux/kthread.h>

extern struct task_struct *monitor_task;
extern atomic_t monitor_should_exit;

void uintr_dump_upid_state(const struct uintr_upid *upid, const char *caller);

char *get_status_str(u8 status);

#endif
