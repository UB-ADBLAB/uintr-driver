#ifndef _INTEL_UINTR_MSR_H
#define _INTEL_UINTR_MSR_H

#include <linux/types.h>

void uintr_msr_set_misc(void *info);

void set_cr4_uintr_bit(void *info);
void clear_cr4_uintr_bit(void *info);

// LOGGING
void dump_uintr_msrs(void *info);

#endif // !_INTEL_UINTR_MSR_H
