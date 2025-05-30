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

void uintr_clear_state(void *info) {
  u64 misc_val;

  /* Clear notification vector in MISC MSR first */
  if (rdmsrl_safe(MSR_IA32_UINTR_MISC, &misc_val)) {
    pr_err("UINTR: Failed to read MISC MSR during clear_state\n");
    return;
  }

  misc_val &= ~(0xFFULL << 32); // Clear notification vector bits
  misc_val |= ((u64)IRQ_VEC_USER << 32);

  if (wrmsrl_safe(MSR_IA32_UINTR_MISC, misc_val) ||
      wrmsrl_safe(MSR_IA32_UINTR_HANDLER, 0) ||
      wrmsrl_safe(MSR_IA32_UINTR_STACKADJUST, 0) ||
      wrmsrl_safe(MSR_IA32_UINTR_PD, 0) || wrmsrl_safe(MSR_IA32_UINTR_RR, 0) ||
      wrmsrl_safe(MSR_IA32_UINTR_TT, 0)) {

    pr_err("UINTR: Failed to clear one or more UINTR MSRs\n");
  }
}

// TODO: change from intel
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
  u32 ndst;

  if (!ctx) {
    pr_err("UINTR: uintr_create_upid called with NULL context\n");
    return -EINVAL;
  }

  task = ctx->task;
  if (!task) {
    pr_err("UINTR: Context has NULL task\n");
    return -EINVAL;
  }

  upid = kzalloc(sizeof(*upid), GFP_KERNEL);
  if (!upid) {
    pr_err("UINTR: Failed to allocate UPID for PID %d\n", task->pid);
    return -ENOMEM;
  }

  // Clear entire structure
  memset(upid, 0, sizeof(*upid));

  ctx->upid = upid;

  cpu = task_cpu(task);
  ndst = cpu_to_ndst(cpu);

  // verify APIC destination
  if (ndst == BAD_APICID) {
    pr_err("UINTR: Invalid APIC ID for CPU %d\n", cpu);
    kfree(upid);
    ctx->upid = NULL;
    return -EINVAL;
  }

  // Initialize UPID fields
  ctx->upid->nc.status = 0;
  ctx->upid->puir = 0;
  ctx->upid->nc.ndst = ndst;
  ctx->upid->nc.nv = IRQ_VEC_USER;

  pr_debug("UINTR: Initialized UPID for process %d on CPU %d (APIC ID: %u)\n",
           task->pid, cpu, ctx->upid->nc.ndst);

  return 0;
}
