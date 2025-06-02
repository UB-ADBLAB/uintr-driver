#include "msr.h"
#include "asm.h"
#include "inteldef.h"
#include "irq.h"
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <linux/kernel.h>
#include <linux/types.h>

void uintr_msr_set_misc(void *info) {
  u64 misc_val;

  // Configure MISC MSR for sender
  rdmsrl(MSR_IA32_UINTR_MISC, misc_val);
  misc_val &= ~GENMASK_ULL(39, 32);
  misc_val &= ~GENMASK_ULL(31, 0);
  misc_val |= ((u64)IRQ_VEC_USER << 32);
  misc_val |= (u64)(UINTR_MAX_UVEC_NR - 1);
  wrmsrl(MSR_IA32_UINTR_MISC, misc_val);
}

void set_cr4_uintr_bit(void *info) {
  unsigned long cr4 = __read_cr4();
  if (!(cr4 & X86_CR4_UINTR)) {
    cr4_set_bits(X86_CR4_UINTR);
    pr_info_once("UINTR: Enabled CR4.UINTR bit across all threads!\n");
  }
}

void clear_cr4_uintr_bit(void *info) {
  unsigned long cr4 = __read_cr4();
  if (cr4 & X86_CR4_UINTR) {
    cr4_clear_bits(X86_CR4_UINTR);
    pr_info_once("UINTR: Cleared CR4.UINTR bit across all threads!\n");
  }
}

void dump_uintr_msrs(void *info) {
  u64 handler_val = 0;
  u64 stack_val = 0;
  u64 misc_val = 0;
  u64 pd_val = 0;
  u64 tt_val = 0;
  u64 rr_val = 0;
  u64 cr4_val = 0;
  int cpu;

  cpu = smp_processor_id();
  cr4_val = __read_cr4();

  rdmsrl(MSR_IA32_UINTR_HANDLER, handler_val);
  rdmsrl(MSR_IA32_UINTR_STACKADJUST, stack_val);
  rdmsrl(MSR_IA32_UINTR_MISC, misc_val);
  rdmsrl(MSR_IA32_UINTR_PD, pd_val);
  rdmsrl(MSR_IA32_UINTR_TT, tt_val);
  rdmsrl(MSR_IA32_UINTR_RR, rr_val);

  pr_debug("UINTR: MSR state on CPU %d:\n", cpu);
  pr_debug("  CR4: 0x%llx (UINTR bit %s)\n", cr4_val,
           (cr4_val & X86_CR4_UINTR) ? "SET" : "NOT SET");
  pr_debug("  HANDLER: 0x%llx\n", handler_val);
  pr_debug("  STACKADJUST: 0x%llx\n", stack_val);
  pr_debug("  MISC: 0x%llx (UINV: 0x%llx)\n", misc_val,
           (misc_val >> 32) & 0xFF);
  pr_debug("  PD: 0x%llx\n", pd_val);
  pr_debug("  TT: 0x%llx (base: 0x%llx, enabled: %lld)\n", tt_val,
           tt_val & ~0xFFF, tt_val & 0x1);
  pr_debug("  RR: 0x%llx\n", rr_val);
  pr_debug("  UIF: 0x%x\n", __testui());
}
