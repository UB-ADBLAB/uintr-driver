#ifndef _INTEL_UINTR_MSR_H
#define _INTEL_UINTR_MSR_H

#include <linux/types.h>

int set_ia32_uintr_tt(u64 uintr_addr);
void set_cr4_uintr_bit(void);
void clear_cr4_uintr_bit(void *info);

// LOGGING
void dump_uintr_msrs(void *info);

#endif // !_INTEL_UINTR_MSR_H
