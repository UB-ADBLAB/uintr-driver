#ifndef _UINTR_IRQ_H_
#define _UINTR_IRQ_H_

#include "driver.h"
#include <linux/interrupt.h>

// TODO: We should set this dynamically.
#define IRQ_VEC_USER 0xeb

irqreturn_t uintr_notification_handler(int irq, void *dev_id);
irqreturn_t uintr_kernel_handler(int irq, void *dev_id);
int uintr_init_irq(struct uintr_device *dev);

#endif
