#include "arch/x86/uintr.h"
#include "core.h"

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <linux/fs.h> // can be removed with uintr_fops
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

static struct uintr_device *uintr_dev;

u32 uintr_max_uitt_entries;
u64 uintr_uitt_base_addr;

// TODO: this is just temporary defined for compiling
const struct file_operations uintr_fops = {
    .owner = THIS_MODULE,
};

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
    pr_err("UINTR: CPU does not support user interrupts.");
    return -EINVAL;
  }

  pr_info("UINTR: Compatible CPU detected (Family: %d, Model: %x)\n", c->x86,
          c->x86_model);

  return 0;
}

static int uintr_uitt_init(void) {
  u64 misc_msr;

  /* Read UITT configuration from MSRs */
  rdmsrl(MSR_IA32_UINTR_MISC, misc_msr);
  uintr_max_uitt_entries = misc_msr & 0xFFFFFFFF; // UITTSZ in bits 31:0

  rdmsrl(MSR_IA32_UINTR_TT, uintr_uitt_base_addr);

  return 0;
}

static int __init uintr_init(void) {
  int ret;

  pr_info("UINTR: Initializing Intel User Interrupts driver v%s\n",
          UINTR_DRIVER_VERSION);

  /* Check CPU compatibility */
  ret = check_cpu_compatibility();
  if (ret < 0)
    return ret;

  ret = uintr_uitt_init();
  if (ret < 0)
    return ret; // currently only returns 0 so should never happen

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
  misc_deregister(&uintr_dev->misc);
  kfree(uintr_dev);
  pr_info("UINTR: Driver unloaded\n");
}

module_init(uintr_init);
module_exit(uintr_exit);

/*
 * TODO: These are required for the kernel module to build, arbitrary values for
 * now.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("UB-ADBLAB");

MODULE_DESCRIPTION("Intel User Interrupts (UINTR) Driver");
MODULE_VERSION(UINTR_DRIVER_VERSION);
