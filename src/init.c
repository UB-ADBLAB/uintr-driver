#include "checks.h"
#include "common.h"
#include "driver.h"
#include "fops.h"
#include "irq.h"
#include "logging/monitor.h"
#include "msr.h"
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

u32 uintr_max_uitt_entries;
u64 uintr_uitt_base_addr;

static void uintr_configure_core(void *info) {
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

  ret = uintr_sched_trace_init();
  if (ret < 0) {
    pr_err("UINTR: Failed to initialize scheduler tracing\n");
    return ret;
  }

  on_each_cpu(uintr_configure_core, (void *)uintr_uitt_base_addr, 1);

  uintr_dev = kzalloc(sizeof(*uintr_dev), GFP_KERNEL);
  if (!uintr_dev)
    return -ENOMEM;

  mutex_init(&uintr_dev->dev_mutex);

  ret = uintr_init_irq(uintr_dev);
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

  pr_info("UINTR: Disabling user interrupts on all CPUs\n");
  on_each_cpu(uintr_clear_state, NULL, 1);

  pr_info("UINTR: Clearing CR4.UINTR bit on all CPUs\n");
  on_each_cpu(clear_cr4_uintr_bit, NULL, 1);

  // Free IRQs
  free_irq(IRQ_VEC_USER, uintr_dev);

  // Clear CR4.UINTR bit on all CPUs
  on_each_cpu(clear_cr4_uintr_bit, NULL, 1);

  synchronize_irq(IRQ_VEC_USER);
  synchronize_rcu();

  uitt_cleanup();

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
