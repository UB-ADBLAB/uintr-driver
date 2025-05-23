#include "state.h"
#include "inteldef.h"
#include "irq.h"
#include "logging/monitor.h"

#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

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
  u64 misc_val;

  // First clear notification vector in MISC MSR to prevent new interrupts
  // This register is finicky when setting values..
  rdmsrl(MSR_IA32_UINTR_MISC, misc_val);
  misc_val &= ~(0xFFULL << 32); // Clear notification vector bits
  misc_val |= ((u64)IRQ_VEC_USER << 32);
  wrmsrl(MSR_IA32_UINTR_MISC, misc_val);

  wrmsrl(MSR_IA32_UINTR_HANDLER, 0);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, 0);
  wrmsrl(MSR_IA32_UINTR_PD, 0);
  wrmsrl(MSR_IA32_UINTR_RR, 0);

  // we shouldn't need to clear the TT msr as the value should be consistent
  // once the driver is loaded.
}

inline u32 cpu_to_ndst(int cpu) {
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

int uintr_create_upid(uintr_process_ctx *ctx) {
  struct task_struct *task;
  struct uintr_upid *upid;
  int cpu;
  if (!ctx)
    return -EINVAL;

  task = ctx->task;

  upid = kzalloc(sizeof(*upid), GFP_KERNEL);

  memset(upid, 0, sizeof(*upid));

  if (!upid)
    return -ENOMEM;

  ctx->upid = upid;

  cpu = task_cpu(task);

  // Initialize UPID
  ctx->upid->nc.status = 0;
  ctx->upid->puir = 0;
  ctx->upid->nc.ndst = cpu_to_ndst(cpu);
  ctx->upid->nc.nv = IRQ_VEC_USER;

  pr_debug("UINTR: Initialized UPID for process %d on CPU %d (APIC ID: %u)\n",
           task->pid, task_cpu(task), ctx->upid->nc.ndst);

  return 0;
}
