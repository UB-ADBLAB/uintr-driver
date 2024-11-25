#ifndef _INTEL_UINTR_CORE_H
#define _INTEL_UINTR_CORE_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "state.h"

// Driver Version
#define UINTR_DRIVER_VERSION "0.1.0"

// Sapphire Rapids CPU identification
#define SPR_FAMILY 0x6 // FAMILY: 6
#define SPR_MODEL 0xCF // MODEL: 207

// Main device driver structure
struct uintr_device {
  struct miscdevice misc;
  struct device *dev;
  struct mutex dev_mutex;
};

struct uintr_file {
  struct uintr_device *uintr_dev;
  struct uintr_process_ctx *proc;
  spinlock_t file_lock;
};

#endif
