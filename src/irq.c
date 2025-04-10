#include "irq.h"
#include "common.h"
#include "msr.h"
#include <asm/apic.h>
#include <asm/irq_regs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

int uintr_init_irq(struct uintr_device *dev) {
  int ret;

  ret = request_threaded_irq(IRQ_VEC_USER, uintr_notification_handler, NULL,
                             IRQF_SHARED | IRQF_NOBALANCING, "uintr_user", dev);

  if (ret < 0) {
    pr_err("UINTR: Failed to request user notification IRQ: %d\n", ret);
    return ret;
  }
  dev->irq_user_vec = IRQ_VEC_USER;

  pr_info("UINTR: Successfully registered IRQ 0x%x\n", IRQ_VEC_USER);
  return 0;
}

irqreturn_t uintr_notification_handler(int irq, void *dev_id) {
  u64 rr_value;

  rdmsrl(MSR_IA32_UINTR_RR, rr_value);

  if (rr_value != 0) {
    pr_info("UINTR: Notification IRQ %d, RR value: 0x%llx\n", irq, rr_value);
  }

  dump_uintr_msrs();

  pr_info("UINTR: User notification received on IRQ %d\n", irq);
  return IRQ_HANDLED;
}

irqreturn_t uintr_kernel_handler(int irq, void *dev_id) {
  // Handle kernel notifications
  pr_info("UINTR: Kernel notification received on IRQ %d\n", irq);
  return IRQ_HANDLED;
}
