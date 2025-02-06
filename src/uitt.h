#ifndef _INTEL_UINTR_UITT_H
#define _INTEL_UINTR_UITT_H

#include "protocol.h"
#include "uintr_types.h"
#include <linux/types.h>

int uitt_init(void);

void uitt_cleanup(void);

int uitt_alloc_entry(struct uintr_process_ctx *proc);

int uitt_free_entry(unsigned int idx);

u64 uitt_get_physical_addr(void);

#endif
