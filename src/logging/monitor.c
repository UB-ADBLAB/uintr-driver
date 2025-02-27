#include "monitor.h"
#include "../state.h"
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/kthread.h>

struct task_struct *monitor_task = NULL;
atomic_t monitor_should_exit = ATOMIC_INIT(0);

// Add mutex to protect monitor task pointer
static DEFINE_MUTEX(monitor_lock);

int upid_monitor_thread(void *data) {
  struct uintr_process_ctx *proc = data;

  if (!proc) {
    pr_err("UINTR: Monitor thread started with NULL proc context\n");
    return -EINVAL;
  }

  pr_info("UINTR: Monitor thread started for process %d\n",
          proc->task ? proc->task->pid : -1);

  // Loop until signaled to exit or kthread_stop is called
  while (!kthread_should_stop() && !atomic_read(&monitor_should_exit)) {
    // Check if process context is still valid
    if (!proc || !proc->upid)
      break;

    // Memory barrier to ensure we see the latest UPID state
    smp_rmb();

    if (proc->upid) {
      // Only log changes, use debug level for routine monitoring
      uintr_monitor_upid_changes(proc->upid, "monitor_thread");
    }

    // Sleep to reduce CPU usage and allow for graceful termination
    msleep(100);
  }

  pr_info("UINTR: Monitor thread exiting\n");
  return 0;
}

// Add these helper functions to safely start/stop the monitor thread
int start_monitor_thread(struct uintr_process_ctx *proc) {
  struct task_struct *new_task;

  if (!proc)
    return -EINVAL;

  mutex_lock(&monitor_lock);

  // Don't start a new thread if one is already running
  if (monitor_task) {
    mutex_unlock(&monitor_lock);
    return 0; // Already running
  }

  // Reset exit flag
  atomic_set(&monitor_should_exit, 0);

  // Create and start the monitor thread
  new_task = kthread_run(upid_monitor_thread, proc, "uintr_monitor");
  if (IS_ERR(new_task)) {
    int err = PTR_ERR(new_task);
    pr_err("UINTR: Failed to create monitor thread, error %d\n", err);
    mutex_unlock(&monitor_lock);
    return err;
  }

  monitor_task = new_task;
  mutex_unlock(&monitor_lock);

  return 0;
}

void stop_monitor_thread(void) {
  mutex_lock(&monitor_lock);

  if (monitor_task) {
    // Signal the thread to exit gracefully
    atomic_set(&monitor_should_exit, 1);

    // Give the thread a moment to see the signal
    msleep(100);

    // Stop the thread if it's still running
    kthread_stop(monitor_task);
    monitor_task = NULL;
  }

  mutex_unlock(&monitor_lock);
}
