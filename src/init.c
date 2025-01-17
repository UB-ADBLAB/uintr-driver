#include "../include/uapi/linux/uintr.h"
#include "arch/x86/uintr.h"
#include "core.h"
#include "fops.h"
#include "proc.h"
#include "protocol.h"
#include "uitt.h"

#include <asm/cpufeature.h>
#include <asm/fpu/xstate.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

#ifndef X86_CR4_UINTR
#define X86_CR4_UINTR (1ULL << 25)
#endif

static struct uintr_device *uintr_dev;
static struct uintr_uitt_manager *uitt_mgr;

u32 uintr_max_uitt_entries;
u64 uintr_uitt_base_addr;

/*
 * check_cpu_compatibility - Verify CPU supports UINTR feature
 *
 * Returns 0 if CPU is compatible, negative error code otherwise
 */
static int check_cpu_compatibility(void) {
  struct cpuinfo_x86 *c = &cpu_data(0);

  /* Verify Intel CPU */
  if (c->x86_vendor != X86_VENDOR_INTEL) {
    pr_err("UINTR: Not an Intel CPU\n");
    return -EINVAL;
  }

  /* Verify Sapphire Rapids */
  if (c->x86 != SPR_FAMILY || c->x86_model != SPR_MODEL) {
    pr_err("UINTR: CPU is not Sapphire Rapids (Family: %d, Model: %x)\n",
           c->x86, c->x86_model);
    return -EINVAL;
  }

  /* Verify UINTR support */
  if (!cpu_have_feature(X86_FEATURE_UINTR)) {
    pr_err("UINTR: CPU does not support user interrupts\n");
    return -EINVAL;
  }

  pr_info("UINTR: Compatible CPU detected (Family: %d, Model: %x)\n", c->x86,
          c->x86_model);
  pr_info("UINTR: CR4: 0x%lx\n", __read_cr4());

  return 0;
}

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
    pr_info("UINTR: Core %d - CR4.UINTR bit enabled!\n", smp_processor_id());
  }
}

static void configure_uintr_tt_on_core(void *info) {
  u64 uintr_addr = (u64)info;

  // Set MSRs and CR4
  set_ia32_uintr_tt(uintr_addr);
  set_cr4_uintr_bit();
}

static int __init uintr_init(void) {
  int ret;

  pr_info("UINTR: Initializing Intel User Interrupts driver v%s\n",
          UINTR_DRIVER_VERSION);

  /* Check CPU compatibility */
  ret = check_cpu_compatibility();
  if (ret < 0)
    return ret;

  ret = uitt_init();
  if (ret < 0)
    return ret;

  uintr_dev = kzalloc(sizeof(*uintr_dev), GFP_KERNEL);
  if (!uintr_dev)
    return -ENOMEM;

  mutex_init(&uintr_dev->dev_mutex);

  /* define misc device */
  uintr_dev->misc.minor = MISC_DYNAMIC_MINOR;
  uintr_dev->misc.name = "uintr";
  uintr_dev->misc.fops = &uintr_fops;

  ret = misc_register(&uintr_dev->misc);
  if (ret) {
    pr_err("UINTR: Failed to register misc device\n");
    kfree(uintr_dev);
    return ret;
  }

  uintr_dev->dev = uintr_dev->misc.this_device;

  pr_info("UINTR: Driver initialized successfully\n");
  return 0;
}

static void __exit uintr_exit(void) {
  // TODO: Currently causes a #GP
  uintr_clear_state();

  if (uitt_mgr) {
    if (uitt_mgr->entries) {
      kfree(uitt_mgr->entries);
    }
    if (uitt_mgr->allocated_vectors) {
      kfree(uitt_mgr->allocated_vectors);
    }
    kfree(uitt_mgr);
  }

  wrmsrl(MSR_IA32_UINTR_TT, 0);

  if (uintr_dev) {
    misc_deregister(&uintr_dev->misc);
    kfree(uintr_dev);
  }
  if (uitt_mgr) {
    kfree(uitt_mgr->allocated_vectors);
    kfree(uitt_mgr->entries);
    kfree(uitt_mgr);
  }
  pr_info("UINTR: Driver unloaded\n");
}

module_init(uintr_init);
module_exit(uintr_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UB-ADBLAB");

MODULE_DESCRIPTION("Intel User Interrupts (UINTR) Driver");
MODULE_VERSION(UINTR_DRIVER_VERSION);
