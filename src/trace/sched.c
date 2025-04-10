#include "sched.h"
#include "../common.h"
#include "../logging/monitor.h"
#include "../msr.h"
#include "../state.h"
#include "linux/smp.h"
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <trace/events/sched.h>

#define UINTR_PROC_HASH_BITS 6 /* 2^6 = 64 buckets for 64 entries */

/* Function to save CPU state (to be called on the source CPU) */
static void save_cpu_state_fn(void *info) {
  struct uintr_process_ctx *proc = (struct uintr_process_ctx *)info;
  if (!proc)
    return;

  int cpu = smp_processor_id();

  pr_info("UINTR: Saving CPU state on %d for UPID %d", cpu, proc->uitt_idx);
  dump_uintr_msrs();

  /* Save the current CPU state to the process context */
  uintr_save_state(&proc->state);
  print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1, &proc->state,
                 sizeof(struct uintr_state), true);
}

/* Function to restore CPU state (to be called on the destination CPU) */
static void restore_cpu_state_fn(void *info) {
  struct uintr_process_ctx *proc = (struct uintr_process_ctx *)info;
  if (!proc)
    return;

  int cpu = smp_processor_id();

  pr_info("UINTR: Restoring CPU state on %d from CPU %d for UPID %d", cpu,
          proc->phys_core, proc->uitt_idx);
  proc->phys_core = cpu;

  /* Restore the CPU state from the process context */
  uintr_restore_state(&proc->state);

  print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1, &proc->state,
                 sizeof(struct uintr_state), true);

  dump_uintr_msrs();
}

static void tracepoint_find(struct tracepoint *tp, void *priv);

/* Structure to store process context mapping */
struct uintr_proc_mapping {
  pid_t pid;
  struct uintr_process_ctx *proc;
  struct hlist_node node;
};

/* Global hash table for PID to proc context mapping */
static DEFINE_HASHTABLE(proc_ctx_hash, UINTR_PROC_HASH_BITS);
static DEFINE_SPINLOCK(proc_ctx_lock);

/* Find a process mapping by PID */
static struct uintr_proc_mapping *find_proc_mapping(pid_t pid) {
  struct uintr_proc_mapping *mapping;

  hash_for_each_possible(proc_ctx_hash, mapping, node, pid) {
    if (mapping->pid == pid) {
      return mapping;
    }
  }

  return NULL;
}

/* Tracepoint handler for sched_migrate_task */
static void uintr_trace_sched_migrate_task(void *data, struct task_struct *p,
                                           int dest_cpu) {
  struct uintr_proc_mapping *mapping;
  struct uintr_process_ctx *proc;
  u32 new_ndst;
  unsigned long flags;
  pid_t pid = p->pid;

  /* Look up the process in our hash table */
  spin_lock_irqsave(&proc_ctx_lock, flags);
  mapping = find_proc_mapping(pid);
  if (mapping) {
    proc = mapping->proc;
  } else {
    proc = NULL;
  }
  spin_unlock_irqrestore(&proc_ctx_lock, flags);

  if (!proc || !proc->upid)
    return;

  /* Calculate the new APIC destination ID based on dest_cpu */
  new_ndst = cpu_to_ndst(dest_cpu);

  /*Must save CPU state here and then reload on the new cpu.*/

  smp_call_function_single(proc->phys_core, save_cpu_state_fn, proc, 1);

  /* Update the notification destination in the UPID */
  if (proc->upid->nc.ndst != new_ndst) {
    spin_lock(&proc->ctx_lock);
    proc->upid->nc.ndst = new_ndst;
    spin_unlock(&proc->ctx_lock);

    pr_info(
        "UINTR: Handler associated process %d migrated to CPU %d from CPU %d\n",
        pid, proc->phys_core, dest_cpu);

    smp_call_function_single(dest_cpu, restore_cpu_state_fn, proc, 1);

    pr_info("UINTR: Restored state for PID %d to CPU %d\n", pid, dest_cpu);

    uintr_dump_upid_state(proc->upid, "sched_migrate");
  }
}

/* The tracepoint symbol */
/* TODO: check if valid */
static struct tracepoint *tp_sched_migrate_task;

/* Callback for for_each_kernel_tracepoint */
static void tracepoint_find(struct tracepoint *tp, void *priv) {
  const char *tp_name = priv;

  if (!strcmp(tp->name, tp_name))
    tp_sched_migrate_task = tp;
}

/* Find the sched_migrate_task tracepoint */
static int find_sched_tracepoints(void) {
  const char *tp_name = "sched_migrate_task";

  /* Reset the global tracepoint pointer */
  tp_sched_migrate_task = NULL;

  /* Attempt to locate tracepoint */
  for_each_kernel_tracepoint(tracepoint_find, (void *)tp_name);

  if (!tp_sched_migrate_task) {
    pr_err("UINTR: Failed to find %s tracepoint\n", tp_name);
    return -EINVAL;
  }

  pr_info("UINTR: Found tracepoint %s\n", tp_name);
  return 0;
}

static int register_sched_tracepoints(void) {
  int ret;

  /* First find the tracepoint */
  ret = find_sched_tracepoints();
  if (ret)
    return ret;

  /* Register our probe with the tracepoint */
  ret = tracepoint_probe_register(tp_sched_migrate_task,
                                  uintr_trace_sched_migrate_task, NULL);
  if (ret) {
    pr_err("UINTR: Failed to register sched_migrate_task tracepoint\n");
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
  struct uintr_proc_mapping *mapping;
  struct hlist_node *tmp;
  unsigned int bkt;

  /* Unregister tracepoints */
  unregister_sched_tracepoints();

  /* Clean up the hash table */
  spin_lock(&proc_ctx_lock);
  hash_for_each_safe(proc_ctx_hash, bkt, tmp, mapping, node) {
    hash_del(&mapping->node);
    kfree(mapping);
  }
  spin_unlock(&proc_ctx_lock);

  pr_info("UINTR: Scheduler tracing cleaned up\n");
}

int uintr_sched_trace_register_proc(struct uintr_process_ctx *proc) {
  struct uintr_proc_mapping *mapping;
  unsigned long flags;

  if (!proc || !proc->task)
    return -EINVAL;

  /* Check if this process is already registered */
  spin_lock_irqsave(&proc_ctx_lock, flags);
  mapping = find_proc_mapping(proc->task->pid);

  if (mapping) {
    /* Update existing mapping */
    mapping->proc = proc;
    spin_unlock_irqrestore(&proc_ctx_lock, flags);
    return 0;
  }

  /* Create a new mapping */
  mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
  if (!mapping) {
    spin_unlock_irqrestore(&proc_ctx_lock, flags);
    return -ENOMEM;
  }

  mapping->pid = proc->task->pid;
  mapping->proc = proc;

  /* Add to hash table */
  hash_add(proc_ctx_hash, &mapping->node, mapping->pid);
  spin_unlock_irqrestore(&proc_ctx_lock, flags);

  /* Initialize NDST to current CPU's APIC ID */
  if (proc->upid) {
    u32 current_ndst = cpu_to_ndst(task_cpu(proc->task));
    if (current_ndst != BAD_APICID) {
      spin_lock(&proc->ctx_lock);
      proc->upid->nc.ndst = current_ndst;
      spin_unlock(&proc->ctx_lock);
    }
  }

  pr_info("UINTR: Registered PID %d for scheduler tracing on CPU %d\n",
          proc->task->pid, task_cpu(proc->task));
  return 0;
}

void uintr_sched_trace_unregister_proc(struct uintr_process_ctx *proc) {
  struct uintr_proc_mapping *mapping;
  unsigned long flags;

  if (!proc || !proc->task)
    return;

  /* Find and remove the mapping */
  spin_lock_irqsave(&proc_ctx_lock, flags);
  mapping = find_proc_mapping(proc->task->pid);
  if (mapping) {
    hash_del(&mapping->node);
    kfree(mapping);
  }
  spin_unlock_irqrestore(&proc_ctx_lock, flags);

  if (mapping) {
    pr_info("UINTR: Unregistered PID %d from scheduler tracing\n",
            proc->task->pid);
  }
}
