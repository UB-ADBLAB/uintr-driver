#ifndef _INTEL_UINTR_MSR_H
#define _INTEL_UINTR_MSR_H

#include <linux/types.h>

static int set_ia32_uintr_tt(u64 uintr_addr);
static void set_cr4_uintr_bit(void);

#endif // !_INTEL_UINTR_MSR_H
