#include "arch/x86/uintr.h"
#include "core.h"

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

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

static int __init uintr_init(void) {
  int ret;

  pr_info("UINTR: Initializing Intel User Interrupts driver v%s\n",
          UINTR_DRIVER_VERSION);

  /* Check CPU compatibility */
  ret = check_cpu_compatibility();
  if (ret < 0)
    return ret;

  pr_info("UINTR: Driver initialized successfully\n");
  return 0;
}

static void __exit uintr_exit(void) { pr_info("UINTR: Driver unloaded\n"); }

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
