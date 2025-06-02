#ifndef _UINTR_STATE_H
#define _UINTR_STATE_H

#include "inteldef.h"
#include <linux/types.h>

struct uintr_device;
struct uintr_process_ctx;

/* xstate management */
void uintr_save_state(struct uintr_state *state);
void uintr_clear_state(void *info);

int uintr_create_upid(uintr_process_ctx *ctx);

inline u32 cpu_to_ndst(int cpu);

#endif
