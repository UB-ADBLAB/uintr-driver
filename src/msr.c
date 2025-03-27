#include "core.h"
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <linux/kernel.h>
#include <linux/types.h>

int set_ia32_uintr_tt(u64 uintr_addr) {
  u64 tt_msr_value;

  if (uintr_addr & ~PAGE_MASK)
    return -EINVAL;

  // Bits 63:12 contain the base address, bit 0 is enable
  tt_msr_value = (uintr_addr & PAGE_MASK) | 0x1;

  pr_info_once("UINTR: Writing MSR value: 0x%llx\n", tt_msr_value);
  wrmsrl(MSR_IA32_UINTR_TT, tt_msr_value);

  return 0;
}

void set_cr4_uintr_bit(void) {
  unsigned long cr4 = __read_cr4();
  if (!(cr4 & X86_CR4_UINTR)) {
    cr4_set_bits(X86_CR4_UINTR);
    pr_info_once("UINTR: CR4.UINTR bit enabled!\n");
    // pr_info("UINTR: Core %d - CR4.UINTR bit enabled!\n", smp_processor_id());
  }
}

void clear_cr4_uintr_bit(void *info) {
  unsigned long cr4 = __read_cr4();
  if (cr4 & X86_CR4_UINTR) {
    cr4_clear_bits(X86_CR4_UINTR);
    pr_info_once("UINTR: CR4.UINTR bit cleared on CPU %d\n",
                 smp_processor_id());
  }
}

void dump_uintr_msrs(void) {
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

  pr_info("UINTR: MSR state on CPU %d:\n", cpu);
  pr_info("  CR4: 0x%llx (UINTR bit %s)\n", cr4_val,
          (cr4_val & X86_CR4_UINTR) ? "SET" : "NOT SET");
  pr_info("  HANDLER: 0x%llx\n", handler_val);
  pr_info("  STACKADJUST: 0x%llx\n", stack_val);
  pr_info("  MISC: 0x%llx (UINV: 0x%llx)\n", misc_val, (misc_val >> 32) & 0xFF);
  pr_info("  PD: 0x%llx\n", pd_val);
  pr_info("  TT: 0x%llx (base: 0x%llx, enabled: %lld)\n", tt_val,
          tt_val & ~0xFFF, tt_val & 0x1);
  pr_info("  RR: 0x%llx\n", rr_val);
}
