#include "state.h"
#include "core.h"
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
  wrmsrl(MSR_IA32_UINTR_MISC, 0);
  wrmsrl(MSR_IA32_UINTR_PD, 0);
  wrmsrl(MSR_IA32_UINTR_TT, 0);
  wrmsrl(MSR_IA32_UINTR_RR, 0);
}

int uintr_init_state(struct uintr_process_ctx *ctx) {
  if (!ctx)
    return -EINVAL;

  INIT_LIST_HEAD(&ctx->vectors);
  spin_lock_init(&ctx->ctx_lock);

  /* TODO: Allocate UPID */

  ctx->handler_active = 0;
  ctx->handler = NULL;
  memset(&ctx->state, 0, sizeof(struct uintr_state));

  return 0;
}

int uintr_setup_sender(struct uintr_uitt *uitt) {
  if (!uitt)
    return -EINVAL;
}
