#ifndef _UINTR_STATE_H
#define _UINTR_STATE_H

#include <linux/types.h>
#include "uintr_types.h"

/* xstate management */
int uintr_init_state(struct uintr_process_ctx *ctx);
void uintr_free_state(struct uintr_process_ctx *ctx);

void uintr_save_state(struct uintr_state *state);
void uintr_restore_state(struct uintr_state *state);
void uintr_clear_state(void);

int uintr_alloc_vector(struct uintr_process_ctx *ctx, __u32 vector);
void uintr_free_vector(struct uintr_vector_ctx *vec_ctx);

// struct uintr_process_ctx *uintr_create_process_ctx(struct task_struct *task);
// void uintr_free_process_ctx(struct uintr_process_ctx *ctx);

#endif
