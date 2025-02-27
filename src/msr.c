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
