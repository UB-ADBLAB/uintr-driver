#ifndef _UINTR_STATE_H
#define _UINTR_STATE_H

#include "uintr_types.h"
#include <linux/types.h>

/* xstate management */
void uintr_save_state(struct uintr_state *state);
void uintr_restore_state(struct uintr_state *state);
void uintr_clear_state(void *info);

int uintr_init_state(struct uintr_process_ctx *ctx);

void uintr_dump_upid_state(const struct uintr_upid *upid, const char *caller);
void uintr_monitor_upid_changes(const struct uintr_upid *upid,
                                const char *caller);

#endif
