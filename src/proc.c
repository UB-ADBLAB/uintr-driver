#include "proc.h"
#include "inteldef.h"
#include "logging/monitor.h"
#include "state.h"
#include "trace/sched.h"
#include "uitt.h"
#include <asm/apic.h>
#include <asm/io.h>
/*#include <linux/hashtable.h>*/
#include <linux/slab.h>
#include <linux/spinlock.h>

// TODO: this function should have better erroring. (?)
uintr_process_ctx *uintr_create_ctx(struct task_struct *task) {
  uintr_process_ctx *ctx;
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

  spin_lock_init(&ctx->ctx_lock);
  ctx->task = task;
  ctx->handler_active = 0;
  ctx->handler = NULL;

  ret = uintr_create_upid(ctx);
  if (ret < 0) {
    kfree(ctx);
    return NULL;
  }

  ret = uintr_sched_trace_register_proc(ctx);
  if (ret < 0) {
    pr_warn("UINTR: Failed to register for scheduler tracing: %d\n", ret);
    return NULL;
  }

  memset(&ctx->state, 0, sizeof(struct uintr_state));

  return ctx;
}

void uintr_destroy_ctx(uintr_process_ctx *ctx) {
  if (!ctx)
    return;

  uintr_sched_trace_unregister_proc(ctx);

  // Clear CPU state
  preempt_disable();

  if (current->pid == ctx->task->pid) {
    uintr_clear_state(NULL);
  }
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
