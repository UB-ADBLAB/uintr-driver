#ifndef _UINTR_STATE_H
#define _UINTR_STATE_H

#include "uintr_types.h"
#include <linux/types.h>

/* xstate management */
void uintr_save_state(struct uintr_state *state);
void uintr_restore_state(struct uintr_state *state);
void uintr_clear_state(void);

int uintr_init_state(struct uintr_process_ctx *ctx);

#endif
