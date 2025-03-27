#ifndef _INTEL_UINTR_UITT_H
#define _INTEL_UINTR_UITT_H

#include "protocol.h"
#include "uintr_types.h"
#include <linux/types.h>

struct uintr_process_ctx *uitt_get_proc_ctx(unsigned int idx);
void uitt_set_proc_ctx(unsigned int idx, struct uintr_process_ctx *proc);

int uitt_init(void);

void uitt_cleanup(void);

int uitt_alloc_entry(struct uintr_process_ctx *proc);

int uitt_free_entry(unsigned int idx);

u64 uitt_get_physical_addr(void);

// logging
void uintr_dump_uitt_entry_state(const struct uintr_uitt_entry *entry, int idx,
                                 const char *caller);

void uintr_dump_uitt_state(const char *caller);

#endif
