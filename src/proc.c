#include "proc.h"
#include "core.h"
#include "logging/monitor.h"
#include "state.h"
#include "uitt.h"
#include <asm/apic.h>
#include <asm/io.h>
/*#include <linux/hashtable.h>*/
#include <linux/slab.h>
#include <linux/spinlock.h>

/*#define UINTR_PROC_HASH_BITS 6 // 2^6 = 64 buckets*/

/*static DEFINE_HASHTABLE(proc_ctx_hash, UINTR_PROC_HASH_BITS);*/
/*static DEFINE_SPINLOCK(proc_ctx_lock);*/

/*static struct uintr_process_ctx *find_proc_ctx(pid_t pid) {*/
/*  struct uintr_process_ctx *ctx;*/
/**/
/*  rcu_read_lock();*/
/*  hash_for_each_possible_rcu(proc_ctx_hash, ctx, hash_node, pid) {*/
/*    if (ctx->pid == pid) {*/
/*      rcu_read_unlock();*/
/*      return ctx;*/
/*    }*/
/*  }*/
/*  rcu_read_unlock();*/
/*  return NULL;*/
/*}*/

/*static int add_proc_ctx(struct uintr_process_ctx *ctx) {*/
/*  spin_lock(&proc_ctx_lock);*/
/*  hash_add_rcu(proc_ctx_hash, &ctx->hash_node, ctx->pid);*/
/*  spin_unlock(&proc_ctx_lock);*/
/*  return 0;*/
/*}*/
/**/
/*static void remove_proc_ctx(struct uintr_process_ctx *ctx) {*/
/*  spin_lock(&proc_ctx_lock);*/
/*  hash_del_rcu(&ctx->hash_node);*/
/*  spin_unlock(&proc_ctx_lock);*/
/*  synchronize_rcu();*/
/*}*/

struct uintr_process_ctx *uintr_proc_create(struct task_struct *task,
                                            struct uintr_device *dev) {
  struct uintr_process_ctx *ctx;
  int ret;

  if (!task) {
    pr_err("UINTR: Tried to create process context where task is NULL!");
    return NULL;
  }

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx) {
    pr_err("UINTR: Failed to allocate memory for process context!");
    return NULL;
  }
  ctx->task = task;

  ret = uintr_init_state(ctx, dev);
  if (ret < 0) {
    kfree(ctx);
    return NULL;
  }

  uintr_dump_upid_state(ctx->upid, "proc_create");

  return ctx;
}

void uintr_proc_destroy(struct uintr_process_ctx *ctx) {
  if (!ctx)
    return;

  // Clear CPU state
  preempt_disable();
  uintr_clear_state(NULL);
  preempt_enable();

  spin_lock(&ctx->ctx_lock);

  // Free UPID
  if (ctx->upid) {
    set_bit(UINTR_UPID_STATUS_SN,
            (unsigned long *)&ctx->upid->nc
                .status); // prevent other interrupts from posting

    smp_wmb();

    kfree(ctx->upid);
    ctx->upid = NULL;
  }

  spin_unlock(&ctx->ctx_lock);

  kfree(ctx);
}

/*static void __trace_sched_migrate_task(void *data, struct task_struct *p,*/
/*                                       int dest_cpu) {*/
/**/
/*  struct uintr_process_ctx *proc_ctx;*/
/**/
/*  ctx = find_proc_ctx(p->pid);*/
/*  if (!ctx)*/
/*    return;*/
/**/
/*  proc_ctx->upid->nc.ndst = cpu_physical_id(dest_cpu);*/
/**/
/*  pr_info("UINTR: Process %d migrated to CPU %d (APIC ID: %u)\n", task->pid,*/
/*          dest_cpu, proc_ctx->upid->nc.ndst);*/
/*}*/
/**/
/*static int init_sched_migrate_tracepoint(void) {*/
/*  int ret;*/
/**/
/*  ret = tracepoint_probe_register("sched_migrate_task",*/
/*                                  __trace_sched_migrate_task, NULL);*/
/*  if (ret) {*/
/*    pr_err("UINTR: Failed to register sched_migrate_task tracepoint\n");*/
/*    return ret;*/
/*  }*/
/**/
/*  return 0;*/
/*}*/
/**/
/*static void cleanup_sched_migrate_tracepoint(void) {*/
/*  tracepoint_probe_unregister("sched_migrate_task",
 * __trace_sched_migrate_task,*/
/*                              NULL);*/
/*}*/
