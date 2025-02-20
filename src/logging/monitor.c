#include "monitor.h"
#include "state.h"
#include <linux/delay.h>

struct task_struct *monitor_task;
atomic_t monitor_should_exit = ATOMIC_INIT(0);

int upid_monitor_thread(void *data) {
  struct uintr_process_ctx *proc = data;

  while (!kthread_should_stop() && !atomic_read(&monitor_should_exit)) {
    if (!proc || !proc->upid)
      break;

    smp_rmb();

    if (proc->upid) {
      uintr_monitor_upid_changes(proc->upid, "monitor_thread");
    }
    msleep(100); // Monitor every 100ms
  }

  return 0;
}
