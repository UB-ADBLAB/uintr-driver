#ifndef _INTEL_UINTR_CORE_H
#define _INTEL_UINTR_CORE_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "state.h"
#include "uitt.h"

// Driver Version
#define UINTR_DRIVER_VERSION "0.1.1"

// Main device driver structure
struct uintr_device {
  struct miscdevice misc;
  struct device *dev;
  struct mutex dev_mutex;
  int irq_user_vec;
  int irq_kern_vec;
};

struct uintr_file {
  struct uintr_device *uintr_dev;
  spinlock_t file_lock;
};

#endif
