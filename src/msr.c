#include <asm/msr.h>
#include <linux/kernel.h>
#include <linux/types.h>

static int set_ia32_uintr_tt(u64 uintr_addr) {
  u64 tt_msr_value;

  // Shift the address to fit into bits 63:4
  uintr_addr >>= 4;

  // Prepare the MSR value:
  // - Bits 63:4 = shifted address
  // - Bit 0 = 1 (SENDUIPI enable)
  tt_msr_value = (uintr_addr & 0xFFFFFFFFFFFFFFF0) | 0x1;

  // Write the value to the IA32_UINTR_TT MSR
  wrmsrl(MSR_IA32_UINTR_TT, tt_msr_value);

  pr_info(
      "UINTR: Core %d - IA32_UINTR_TT MSR set to 0x%llx (UINTRADDR = 0x%llx)\n",
      smp_processor_id(), tt_msr_value, uintr_addr << 4);

  return 0;
}

static void set_cr4_uintr_bit(void) {
  unsigned long cr4 = __read_cr4();
  if (!(cr4 & X86_CR4_UINTR)) {
    cr4_set_bits(X86_CR4_UINTR);
    pr_info_once("UINTR: CR4.UINTR bit enabled!\n");
    // pr_info("UINTR: Core %d - CR4.UINTR bit enabled!\n", smp_processor_id());
  }
}
