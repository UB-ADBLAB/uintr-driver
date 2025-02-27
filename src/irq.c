#include "core.h"
#include <asm/apic.h>
#include <asm/irq_regs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

static irqreturn_t uintr_notification_handler(int irq, void *dev_id);
static irqreturn_t uintr_kernel_handler(int irq, void *dev_id);
static int setup_uintr_vectors(struct uintr_device *dev);

#define IRQ_VEC_USER                                                           \
  0xeb // We should set this dynamically.. may be more complicated then
       // expected.

static int setup_uintr_vectors(struct uintr_device *dev) {
  int ret;

  ret = request_any_context_irq(IRQ_VEC_USER, uintr_notification_handler,
                                IRQF_SHARED, "uintr_user", dev);
  if (ret < 0) {
    pr_err("UINTR: Failed to request user notification IRQ: %d\n", ret);
    return ret;
  }
  dev->irq_user_vec = ret;

  return 0;
}
static irqreturn_t uintr_notification_handler(int irq, void *dev_id) {
  // Handle user notifications

  // We don't need to explicitly call the handler function as the hardware
  // should handle this for us.

  native_apic_mem_write(APIC_EOI, 0); // TODO: is this necessary?

  pr_info("UINTR: User notification received on IRQ %d\n", irq);
  return IRQ_HANDLED;
}

static irqreturn_t uintr_kernel_handler(int irq, void *dev_id) {
  // Handle kernel notifications
  pr_info("UINTR: Kernel notification received on IRQ %d\n", irq);
  return IRQ_HANDLED;
}
