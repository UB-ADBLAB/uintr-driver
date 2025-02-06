#include "state.h"
#include "core.h"
#include "proc.h"

#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

void uintr_save_state(struct uintr_state *state) {
  if (!state)
    return;

  rdmsrl(MSR_IA32_UINTR_HANDLER, state->handler);
  rdmsrl(MSR_IA32_UINTR_STACKADJUST, state->stack_adjust);
  rdmsrl(MSR_IA32_UINTR_MISC, *(u64 *)&state->misc);
  rdmsrl(MSR_IA32_UINTR_PD, state->upid_addr);
  rdmsrl(MSR_IA32_UINTR_TT, state->uitt_addr);
  rdmsrl(MSR_IA32_UINTR_RR, state->uirr);
}

void uintr_restore_state(struct uintr_state *state) {
  if (!state)
    return;

  wrmsrl(MSR_IA32_UINTR_HANDLER, state->handler);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, state->stack_adjust);
  wrmsrl(MSR_IA32_UINTR_MISC, *(u64 *)&state->misc);
  wrmsrl(MSR_IA32_UINTR_PD, state->upid_addr);
  wrmsrl(MSR_IA32_UINTR_TT, state->uitt_addr);
  wrmsrl(MSR_IA32_UINTR_RR, state->uirr);
}

void uintr_clear_state(void) {
  wrmsrl(MSR_IA32_UINTR_HANDLER, 0);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, 0);
  wrmsrl(MSR_IA32_UINTR_MISC,
         0); // TODO: We should only clear the correct bits with a masking here.
  wrmsrl(MSR_IA32_UINTR_PD, 0);
  wrmsrl(MSR_IA32_UINTR_TT, 0);
  wrmsrl(MSR_IA32_UINTR_RR, 0);
}

int uintr_init_state(struct uintr_process_ctx *ctx) {
  struct task_struct *task;
  struct uintr_upid *upid;
  if (!ctx)
    return -EINVAL;

  task = ctx->task;
  spin_lock_init(&ctx->ctx_lock);

  upid = kzalloc(sizeof(*upid),
                 GFP_KERNEL); // vmalloc_user( sizeof(struct uintr_upid));
                              // TODO: How should upid/uitt be addressed? user
                              // space, kernel space, or physical?

  if (!upid)
    return -ENOMEM;

  ctx->upid = upid;

  // Initialize UPID
  ctx->upid->nc.status = 0;
  ctx->upid->puir = 0;
  ctx->upid->nc.ndst = cpu_physical_id(task_cpu(task));
  ctx->upid->nc.nv = UINTR_NOTIFICATION_VECTOR;

  ctx->handler_active = 0;
  ctx->handler = NULL;

  pr_info("UINTR: Registered handler for process %d on CPU %d (APIC ID: %u)\n",
          task->pid, task_cpu(task), ctx->upid->nc.ndst);

  memset(&ctx->state, 0, sizeof(struct uintr_state));

  return 0;
}
