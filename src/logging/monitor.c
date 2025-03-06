#include "monitor.h"
#include "../state.h"
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/kthread.h>

struct task_struct *monitor_task = NULL;
atomic_t monitor_should_exit = ATOMIC_INIT(0);

static struct uintr_upid prev_state;
static bool is_first_check = true;

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
    if (!proc || !proc->upid)
      break;

    // Memory barrier to ensure we see the latest UPID state
    smp_rmb();

    if (proc->upid) {
      // only log changes
      uintr_monitor_upid_changes(proc->upid, "monitor_thread");
    }

    msleep(100);
  }

  pr_info("UINTR: Monitor thread exiting\n");
  return 0;
}

int start_monitor_thread(struct uintr_process_ctx *proc) {
  struct task_struct *new_task;

  if (!proc)
    return -EINVAL;

  mutex_lock(&monitor_lock);

  // dont start if thread is already running
  if (monitor_task) {
    mutex_unlock(&monitor_lock);
    return 0;
  }

  atomic_set(&monitor_should_exit, 0);

  // start the monitor thread
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

    msleep(100);

    // Stop the thread if it's still running
    kthread_stop(monitor_task);
    monitor_task = NULL;
  }

  mutex_unlock(&monitor_lock);
}

void uintr_dump_upid_state(const struct uintr_upid *upid, const char *caller) {
  if (!upid) {
    pr_info("UINTR [%s]: UPID is NULL\n", caller);
    return;
  }

  pr_info("UINTR [%s]: UPID State:\n", caller);
  pr_info("  Raw memory (64 bytes):");
  print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1, upid,
                 sizeof(struct uintr_upid), true);

  pr_info("  Status: %s (0x%x)\n", get_status_str(upid->nc.status),
          upid->nc.status);
  pr_info("  Notification Vector: 0x%x\n", upid->nc.nv);
  pr_info("  Notification Dest: 0x%x\n", upid->nc.ndst);
  pr_info("  Posted Interrupts: 0x%llx\n", upid->puir);
}

void uintr_monitor_upid_changes(const struct uintr_upid *upid,
                                const char *caller) {
  if (!upid) {
    pr_debug("UINTR [%s]: UPID is NULL\n", caller);
    return;
  }

  if (is_first_check) {
    memcpy(&prev_state, upid, sizeof(prev_state));
    is_first_check = false;
    uintr_dump_upid_state(upid, caller);
    return;
  }

  bool changed = false;

  if (prev_state.nc.status != upid->nc.status) {
    pr_info("UINTR [%s]: Status changed: %s -> %s\n", caller,
            get_status_str(prev_state.nc.status),
            get_status_str(upid->nc.status));
    changed = true;
  }

  if (prev_state.nc.nv != upid->nc.nv) {
    pr_info("UINTR [%s]: Notification vector changed: 0x%x -> 0x%x\n", caller,
            prev_state.nc.nv, upid->nc.nv);
    changed = true;
  }

  if (prev_state.nc.ndst != upid->nc.ndst) {
    pr_info("UINTR [%s]: Notification dest changed: 0x%x -> 0x%x\n", caller,
            prev_state.nc.ndst, upid->nc.ndst);
    changed = true;
  }

  if (prev_state.puir != upid->puir) {
    pr_info("UINTR [%s]: Posted interrupts changed: 0x%llx -> 0x%llx\n", caller,
            prev_state.puir, upid->puir);
    changed = true;
  }

  if (!changed) {
    pr_info("UINTR [%s]: No changes detected\n", caller);
  }

  // update previous state
  memcpy(&prev_state, upid, sizeof(prev_state));
}

char *get_status_str(u8 status) {
  if (status & (1 << UINTR_UPID_STATUS_BLKD))
    return "BLKD";
  if (status & (1 << UINTR_UPID_STATUS_SN))
    return "SN";
  if (status & (1 << UINTR_UPID_STATUS_ON))
    return "ON";
  return "OFF";
}
