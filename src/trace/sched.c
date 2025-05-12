#include "sched.h"
#include "../inteldef.h"
#include "../logging/monitor.h"
#include "../mappings/proc_mapping.h"
#include "../msr.h"
#include "../state.h"
#include "asm/paravirt.h"
#include "linux/smp.h"
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <trace/events/sched.h>

struct migration_info {
  struct uintr_proc_mapping *map;
  int dest_cpu;
};

/* Function to save CPU state (to be called on the source CPU) */
static void save_cpu_state_fn(void *info) {
  struct migration_info *mig_info = (struct migration_info *)info;

  if (!mig_info || !mig_info->map) {
    pr_warn("UINTR: save_cpu_state_fn called with bad args!\n");
    return;
  }

  if (mig_info->map->ctx) {
    uintr_process_ctx *ctx = mig_info->map->ctx;

    if (!ctx->upid) {
      pr_warn("UINTR: Process context has NULL UPID\n");
      return;
    }

    pr_info("UINTR: Saving CPU state for process %d, migrating to CPU %d\n",
            ctx->task->pid, mig_info->dest_cpu);

    // update ndst to new cpu
    ctx->upid->nc.ndst = cpu_to_ndst(mig_info->dest_cpu);

    rdmsrl(MSR_IA32_UINTR_HANDLER, ctx->state.handler);
    rdmsrl(MSR_IA32_UINTR_STACKADJUST, ctx->state.stack_adjust);
    rdmsrl(MSR_IA32_UINTR_MISC, *(u64 *)&ctx->state.misc);
    rdmsrl(MSR_IA32_UINTR_PD, ctx->state.upid_addr);
    rdmsrl(MSR_IA32_UINTR_RR, ctx->state.uirr);

    // currently unused
    rdmsrl(MSR_IA32_UINTR_TT, ctx->state.uitt_addr);
    dump_uintr_msrs(NULL);
  }
}

/* Function to restore CPU state (to be called on the destination CPU) */
static void restore_cpu_state_fn(void *info) {
  struct uintr_proc_mapping *mapping = (struct uintr_proc_mapping *)info;

  if (!mapping) {
    pr_warn("UINTR: restore_cpu_state_fn called with bad args!\n");
    return;
  }

  if (mapping->ctx) {
    struct uintr_state state = mapping->ctx->state;
    wrmsrl(MSR_IA32_UINTR_HANDLER, state.handler);
    wrmsrl(MSR_IA32_UINTR_STACKADJUST, state.stack_adjust);
    wrmsrl(MSR_IA32_UINTR_MISC, *(u64 *)&state.misc);
    wrmsrl(MSR_IA32_UINTR_PD, state.upid_addr);
    wrmsrl(MSR_IA32_UINTR_RR, state.uirr);
  }

  if (mapping->uitt) {
    wrmsrl(MSR_IA32_UINTR_TT, (u64)mapping->uitt->entries | 1);
  }
}

static void tracepoint_find(struct tracepoint *tp, void *priv);

static void uintr_trace_sched_switch(void *data, bool preempt,
                                     struct task_struct *prev,
                                     struct task_struct *next) {
  /*
   * When a task switch occurs, check if the next task needs UINTR state updated
   * on the current CPU
   */
  uintr_update_cpu_state(next);
}

/* Tracepoint handler for sched_migrate_task */
static void uintr_trace_sched_migrate_task(void *data, struct task_struct *p,
                                           int dest_cpu) {
  struct uintr_proc_mapping *mapping;
  uintr_process_ctx *proc;
  int source_cpu, new_ndst;
  pid_t pid = p->pid;

  mapping = find_proc_mapping(pid);
  if (!mapping) {
    return; // process is not a pid we are tracking, ignore
  }

  struct migration_info info = {
      .dest_cpu = dest_cpu,
      .map = mapping,
  };

  source_cpu = task_cpu(p);

  /*Must save CPU state here and then reload on the new cpu.*/
  smp_call_function_single(source_cpu, save_cpu_state_fn, &info, 1);

  pr_info("UINTR: Tracked process %d migrated to CPU %d from CPU %d\n", pid,
          source_cpu, dest_cpu);

  // restore state on our dest_cpu
  smp_call_function_single(dest_cpu, restore_cpu_state_fn, mapping, 1);

  pr_info("UINTR: State restored for PID %d to CPU %d\n", pid, dest_cpu);
}

/* The tracepoint symbols */
static struct tracepoint *tp_sched_migrate_task;
static struct tracepoint *tp_sched_switch;

/* Callback for for_each_kernel_tracepoint */
static void tracepoint_find(struct tracepoint *tp, void *priv) {
  const char *tp_name = priv;

  if (!strcmp(tp->name, tp_name)) {
    if (!strcmp(tp_name, "sched_migrate_task"))
      tp_sched_migrate_task = tp;
    else if (!strcmp(tp_name, "sched_switch"))
      tp_sched_switch = tp;
  }
}

/* Find the sched_migrate_task tracepoint */
static int find_sched_tracepoints(void) {
  /* Reset the global tracepoint pointer */
  tp_sched_migrate_task = NULL;
  tp_sched_switch = NULL;

  /* Attempt to locate migrate tracepoint */
  for_each_kernel_tracepoint(tracepoint_find, (void *)"sched_migrate_task");
  if (!tp_sched_migrate_task) {
    pr_err("UINTR: Failed to find sched_migrate_task tracepoint\n");
    return -EINVAL;
  }

  /* Attempt to locate switch tracepoint */
  for_each_kernel_tracepoint(tracepoint_find, (void *)"sched_switch");
  if (!tp_sched_switch) {
    pr_err("UINTR: Failed to find sched_switch tracepoint\n");
    return -EINVAL;
  }

  pr_info("UINTR: Found tracepoints \n");
  return 0;
}

static int register_sched_tracepoints(void) {
  int ret;

  /* First find the tracepoints */
  ret = find_sched_tracepoints();
  if (ret)
    return ret;

  /* Register our probes with the tracepoints */
  ret = tracepoint_probe_register(tp_sched_migrate_task,
                                  uintr_trace_sched_migrate_task, NULL);
  if (ret) {
    pr_err("UINTR: Failed to register sched_migrate_task tracepoint\n");
    return ret;
  }

  ret = tracepoint_probe_register(tp_sched_switch, uintr_trace_sched_switch,
                                  NULL);
  if (ret) {
    tracepoint_probe_unregister(tp_sched_migrate_task,
                                uintr_trace_sched_migrate_task, NULL);
    pr_err("UINTR: Failed to register sched_switch tracepoint\n");
    return ret;
  }

  return 0;
}

/* Tracepoint probe unregistration function */
static void unregister_sched_tracepoints(void) {
  if (tp_sched_migrate_task) {
    tracepoint_probe_unregister(tp_sched_migrate_task,
                                uintr_trace_sched_migrate_task, NULL);
    tp_sched_migrate_task = NULL;
  }

  if (tp_sched_switch) {
    tracepoint_probe_unregister(tp_sched_switch, uintr_trace_sched_switch,
                                NULL);
    tp_sched_switch = NULL;
  }
}

int uintr_sched_trace_init(void) {
  int ret;

  /* Register tracepoints */
  ret = register_sched_tracepoints();
  if (ret)
    return ret;

  pr_info("UINTR: Scheduler tracing initialized\n");
  return 0;
}

void uintr_sched_trace_cleanup(void) {
  /* Unregister tracepoints */
  unregister_sched_tracepoints();

  proc_mapping_cleanup();

  pr_info("UINTR: Scheduler tracing cleaned up\n");
}
