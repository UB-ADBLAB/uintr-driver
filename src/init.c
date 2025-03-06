#include "core.h"
#include "fops.h"
#include "irq.c"
#include "logging/monitor.h"
#include "msr.h"
#include "protocol.h"
#include "trace/sched.h"
#include "uitt.h"

#include <asm/cpufeature.h>
#include <asm/fpu/xstate.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

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

// TODO: rename and move this
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

  on_each_cpu(configure_uintr_tt_on_core, (void *)uintr_uitt_base_addr, 1);

  uintr_dev = kzalloc(sizeof(*uintr_dev), GFP_KERNEL);
  if (!uintr_dev)
    return -ENOMEM;

  mutex_init(&uintr_dev->dev_mutex);

  ret = setup_uintr_vectors(uintr_dev);
  if (ret < 0) {
    kfree(uintr_dev);
    return ret;
  }

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

  // TODO: do we need to suppress interrupts first?
  uintr_sched_trace_cleanup();

  if (monitor_task) {
    pr_info("UINTR: Stopping monitor thread...\n");
    stop_monitor_thread();
  }

  pr_info("UINTR: Disabling user interrupts on all CPUs\n");
  on_each_cpu(uintr_clear_state, NULL, 1);

  pr_info("UINTR: Clearing CR4.UINTR bit on all CPUs\n");
  on_each_cpu(clear_cr4_uintr_bit, NULL, 1);

  // Free IRQs
  if (uintr_dev) {
    if (uintr_dev->irq_user_vec)
      free_irq(uintr_dev->irq_user_vec, uintr_dev);
    if (uintr_dev->irq_kern_vec)
      free_irq(uintr_dev->irq_kern_vec, uintr_dev);
  }

  // Clear CR4.UINTR bit on all CPUs
  on_each_cpu(clear_cr4_uintr_bit, NULL, 1);

  // Clean up UITT
  if (uitt_mgr) {
    if (uitt_mgr->uitt) {
      if (uitt_mgr->uitt->entries) {
        free_pages(
            (unsigned long)uitt_mgr->uitt->entries,
            get_order(uitt_mgr->uitt->size * sizeof(struct uintr_uitt_entry)));
        uitt_mgr->uitt->entries = NULL;
      }
      kfree(uitt_mgr->uitt);
      uitt_mgr->uitt = NULL;
    }
    kfree(uitt_mgr);
    uitt_mgr = NULL;
  }

  // Unregister device
  if (uintr_dev) {
    misc_deregister(&uintr_dev->misc);
    mutex_destroy(&uintr_dev->dev_mutex);
    kfree(uintr_dev);
    uintr_dev = NULL;
  }

  pr_info("UINTR: Driver unloaded\n");
}

module_init(uintr_init);
module_exit(uintr_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UB-ADBLAB");

MODULE_DESCRIPTION("Intel User Interrupts (UINTR) Driver");
MODULE_VERSION(UINTR_DRIVER_VERSION);
