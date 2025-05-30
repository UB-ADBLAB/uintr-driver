#include "sched.h"
#include "../asm.h"
#include "../inteldef.h"
#include "../logging/monitor.h"
#include "../mappings/proc_mapping.h"
#include "../msr.h"
#include "../proc.h"
#include "../state.h"
#include "../uitt.h"

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <trace/events/sched.h>

// saves state on a logical cpu
static void uintr_state_save(uintr_process_ctx *ctx) {
  if (!ctx)
    return;

  spin_lock(&ctx->ctx_lock);

  // Save MSRs based on role
  if (ctx->role & UINTR_RECEIVER) {
    // Suppress further notifications
    set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&ctx->upid->nc.status);

    // Save UIF state
    ctx->state.misc.uif = __testui();

    // Save receiver MSRs
    rdmsrl(MSR_IA32_UINTR_HANDLER, ctx->state.handler);
    rdmsrl(MSR_IA32_UINTR_STACKADJUST, ctx->state.stack_adjust);
    rdmsrl(MSR_IA32_UINTR_PD, ctx->state.upid_addr);
    rdmsrl(MSR_IA32_UINTR_RR, ctx->state.uirr);
  }

  if (ctx->role & UINTR_SENDER) {
    // Save sender MSR
    rdmsrl(MSR_IA32_UINTR_TT, ctx->state.uitt_addr);
  }

  spin_unlock(&ctx->ctx_lock);
}

// restores state on a logical cpu
static void uintr_state_restore(uintr_process_ctx *ctx) {
  if (!ctx)
    return;

  spin_lock(&ctx->ctx_lock);

  // Restore MSRs based on role
  if (ctx->role & UINTR_RECEIVER) {
    ctx->upid->nc.ndst = cpu_to_ndst(raw_smp_processor_id());
    smp_wmb();

    // Restore receiver MSRs
    wrmsrl(MSR_IA32_UINTR_HANDLER, ctx->state.handler);
    wrmsrl(MSR_IA32_UINTR_STACKADJUST, ctx->state.stack_adjust);
    wrmsrl(MSR_IA32_UINTR_PD, ctx->state.upid_addr);
    wrmsrl(MSR_IA32_UINTR_RR, ctx->state.uirr);

    // Restore UIF state
    if (ctx->state.misc.uif)
      __stui();
    else
      __clui();

    // Clear suppress notification bit
    clear_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&ctx->upid->nc.status);
  }

  if (ctx->role & UINTR_SENDER) {
    // Restore sender MSR
    wrmsrl(MSR_IA32_UINTR_TT, ctx->state.uitt_addr);
  }

  // MISC MSR is common to both roles.
  uintr_msr_set_misc(NULL);

  spin_unlock(&ctx->ctx_lock);
}

// ---------------------------------------------------------------------------
// Tracepoint callbacks

// sched_migrate_task – update NDST in UPID for receivers
static void tp_sched_migrate_task_cb(void *ignore, struct task_struct *p,
                                     int dest_cpu) {
  uintr_process_ctx *ctx = find_process_ctx(p->pid);
  if (ctx && (ctx->role & UINTR_RECEIVER) && ctx->upid) {
    ctx->upid->nc.ndst = cpu_to_ndst(dest_cpu);
  }
}

// sched_switch – save prev, restore next
static void tp_sched_switch_cb(void *ignore, bool preempt,
                               struct task_struct *prev,
                               struct task_struct *next) {
  uintr_process_ctx *ctx;

  // Save state for prev task
  if (prev) {
    ctx = find_process_ctx(prev->pid);
    if (ctx) {
      uintr_state_save(ctx);
    }
  }

  // Restore state for next task
  if (next) {
    ctx = find_process_ctx(next->pid);
    if (ctx) {
      uintr_state_restore(ctx);
    }
  }
}

// sched_process_exit – final cleanup
static void tp_sched_process_exit_cb(void *ignore, struct task_struct *p) {
  uintr_process_ctx *ctx = find_process_ctx(p->pid);
  if (!ctx)
    return;

  // Save state one last time
  uintr_state_save(ctx);

  // Clear MSRs
  uintr_clear_state(NULL);

  // Clean up based on role
  if (ctx->role & UINTR_RECEIVER) {
    // UPID cleanup is handled in uintr_destroy_ctx
  }

  if (ctx->role & UINTR_SENDER) {
    if (ctx->uitt) {
      uitt_cleanup(ctx->uitt);
      ctx->uitt = NULL;
    }
  }

  // Remove from process mapping and destroy context
  remove_process_mapping(p->pid);
  uintr_destroy_ctx(ctx);
}

// ---------------------------------------------------------------------------
// Tracepoint plumbing & initalization

static struct tracepoint *tp_sched_migrate_task;
static struct tracepoint *tp_sched_switch;
static struct tracepoint *tp_sched_process_exit;

static void find_tracepoint(struct tracepoint *tp, void *priv) {
  const char *name = priv;
  if (!strcmp(tp->name, name)) {
    if (!strcmp(name, "sched_migrate_task"))
      tp_sched_migrate_task = tp;
    else if (!strcmp(name, "sched_switch"))
      tp_sched_switch = tp;
    else if (!strcmp(name, "sched_process_exit"))
      tp_sched_process_exit = tp;
  }
}

static int locate_tracepoints(void) {
  tp_sched_migrate_task = NULL;
  tp_sched_switch = NULL;
  tp_sched_process_exit = NULL;

  for_each_kernel_tracepoint(find_tracepoint, (void *)"sched_migrate_task");
  for_each_kernel_tracepoint(find_tracepoint, (void *)"sched_switch");
  for_each_kernel_tracepoint(find_tracepoint, (void *)"sched_process_exit");

  if (!tp_sched_migrate_task || !tp_sched_switch || !tp_sched_process_exit) {
    pr_err("UINTR: required scheduler tracepoints not found\n");
    return -EINVAL;
  }
  return 0;
}

static int register_tracepoints(void) {
  int ret = locate_tracepoints();
  if (ret)
    return ret;

  ret = tracepoint_probe_register(tp_sched_migrate_task,
                                  tp_sched_migrate_task_cb, NULL);
  if (ret)
    return ret;

  ret = tracepoint_probe_register(tp_sched_switch, tp_sched_switch_cb, NULL);
  if (ret) {
    tracepoint_probe_unregister(tp_sched_migrate_task, tp_sched_migrate_task_cb,
                                NULL);
    return ret;
  }

  ret = tracepoint_probe_register(tp_sched_process_exit,
                                  tp_sched_process_exit_cb, NULL);
  if (ret) {
    tracepoint_probe_unregister(tp_sched_switch, tp_sched_switch_cb, NULL);
    tracepoint_probe_unregister(tp_sched_migrate_task, tp_sched_migrate_task_cb,
                                NULL);
  }
  return ret;
}

static void unregister_tracepoints(void) {
  if (tp_sched_process_exit)
    tracepoint_probe_unregister(tp_sched_process_exit, tp_sched_process_exit_cb,
                                NULL);
  if (tp_sched_switch)
    tracepoint_probe_unregister(tp_sched_switch, tp_sched_switch_cb, NULL);
  if (tp_sched_migrate_task)
    tracepoint_probe_unregister(tp_sched_migrate_task, tp_sched_migrate_task_cb,
                                NULL);
}

int uintr_sched_trace_init(void) {
  int ret = register_tracepoints();
  if (!ret)
    pr_info("UINTR: Scheduler tracing initialized\n");
  return ret;
}

void uintr_sched_trace_cleanup(void) {
  unregister_tracepoints();
  proc_mapping_cleanup();
  pr_info("UINTR: Scheduler tracing cleaned up\n");
}
