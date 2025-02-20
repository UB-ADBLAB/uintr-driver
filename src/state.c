#include "state.h"
#include "core.h"
#include "proc.h"

#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

static struct uintr_upid prev_state;
static bool is_first_check = true;

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

void uintr_clear_state(void *info) {
  wrmsrl(MSR_IA32_UINTR_HANDLER, 0);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, 0);
  wrmsrl(MSR_IA32_UINTR_MISC,
         0); // TODO: We should only clear the correct bits with a masking here.
  wrmsrl(MSR_IA32_UINTR_PD, 0);
  wrmsrl(MSR_IA32_UINTR_TT, 0);
  wrmsrl(MSR_IA32_UINTR_RR, 0);
}

static inline u32 cpu_to_ndst(int cpu) {
  u32 apicid;

// Get APIC ID for the CPU
#ifdef CONFIG_X86_X2APIC
  // For x2APIC mode
  apicid = per_cpu(x86_cpu_to_apicid, cpu);
#else
  // For xAPIC mode
  apicid = per_cpu(x86_bios_cpu_apicid, cpu);
#endif

  // Check for invalid APIC ID
  if (apicid == BAD_APICID) {
    pr_warn("UINTR: Invalid APIC ID for CPU %d\n", cpu);
    return BAD_APICID;
  }

  // Format based on APIC mode
  if (!x2apic_enabled()) {
    // xAPIC mode: shift APIC ID to bits 8-15
    return (apicid << 8) & 0xFF00;
  }

  // x2APIC mode: use APIC ID directly
  return apicid;
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
  ctx->upid->nc.ndst = cpu_to_ndst(task_cpu(task));
  ctx->upid->nc.nv = UINTR_NOTIFICATION_VECTOR;

  ctx->handler_active = 0;
  ctx->handler = NULL;

  pr_info("UINTR: Initalized UPID for process %d on CPU %d (APIC ID: %u)\n",
          task->pid, task_cpu(task), ctx->upid->nc.ndst);

  memset(&ctx->state, 0, sizeof(struct uintr_state));

  return 0;
}

static const char *get_status_str(u8 status) {
  if (status & (1 << UINTR_UPID_STATUS_BLKD))
    return "BLKD";
  if (status & (1 << UINTR_UPID_STATUS_SN))
    return "SN";
  if (status & (1 << UINTR_UPID_STATUS_ON))
    return "ON";
  return "OFF";
}

void uintr_dump_upid_state(const struct uintr_upid *upid, const char *caller) {
  if (!upid) {
    pr_info("UINTR [%s]: UPID is NULL\n", caller);
    return;
  }

  pr_info("UINTR [%s]: UPID State:\n", caller);
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

  // Update previous state
  memcpy(&prev_state, upid, sizeof(prev_state));
}
