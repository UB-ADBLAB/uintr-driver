#include "proc.h"
#include "asm.h"
#include "inteldef.h"
#include "logging/monitor.h"
#include "mappings/proc_mapping.h"
#include "state.h"
#include "trace/sched.h"
#include "uitt.h"
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

// Create a new context for a process
uintr_process_ctx *uintr_create_ctx(struct task_struct *task) {
  uintr_process_ctx *ctx;

  if (!task) {
    pr_err("UINTR: Tried to create process context where task is NULL!");
    return NULL;
  }

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx) {
    pr_err("UINTR: Failed to allocate memory for process context!");
    return NULL;
  }

  spin_lock_init(&ctx->ctx_lock);
  ctx->task = task;
  ctx->role = UINTR_NONE;

  // Initialize receiver state
  ctx->handler = NULL;
  ctx->upid = NULL;

  // Initialize sender state
  ctx->uitt = NULL;

  // Clear MSR state
  memset(&ctx->state, 0, sizeof(struct uintr_state));

  return ctx;
}

void uintr_destroy_ctx(uintr_process_ctx *ctx) {
  unsigned long flags;

  if (!ctx)
    return;

  /* CRITICAL: Disable interrupts and clear MSRs if this is the current process
   */
  if (current->pid == ctx->task->pid) {
    __clui(); /* Disable user interrupts first */
    preempt_disable();
    uintr_clear_state(NULL); /* Clear all MSRs */
    preempt_enable();
  }

  spin_lock_irqsave(&ctx->ctx_lock, flags);

  /* Free receiver resources */
  if (ctx->upid) {
    /* Set suppress notification bit to prevent further interrupts */
    set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&ctx->upid->nc.status);
    smp_wmb();

    kfree(ctx->upid);
    ctx->upid = NULL;
  }

  /* Free sender resources */
  if (ctx->uitt) {
    uitt_cleanup(ctx->uitt);
    ctx->uitt = NULL;
  }

  /* Clear handler pointer */
  ctx->handler = NULL;
  ctx->role = UINTR_NONE;

  spin_unlock_irqrestore(&ctx->ctx_lock, flags);

  kfree(ctx);
}
