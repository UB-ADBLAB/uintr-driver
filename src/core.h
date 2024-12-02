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

// MSRs as specified in Intel SDM
#define MSR_IA32_UINTR_RR 0x985
#define MSR_IA32_UINTR_HANDLER 0x986
#define MSR_IA32_UINTR_STACKADJUST 0x987
#define MSR_IA32_UINTR_MISC 0x988
#define MSR_IA32_UINTR_PD 0x989
#define MSR_IA32_UINTR_TT 0x98a

#define X86_FEATURE_UINTR (18 * 32 + 5) /* User Interrupts support */

/* UITT configuration -- needs to be initalized during driver set up */
extern u32 uintr_max_uitt_entries;
extern u64 uintr_uitt_base_addr;

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
