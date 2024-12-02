#ifndef _UINTR_STATE_H
#define _UINTR_STATE_H

#include <linux/types.h>

struct uintr_process_ctx;

/* xstate structure - 48 byte total */
/* See Intel SDM 13.5.11 */
struct uintr_state {
  u64 handler;
  u64 stack_adjust;
  struct {
    u32 uitt_size;
    u8 uinv;
    u8 pad1;
    u8 pad2;
    union { /* byte 23 = pad3 OR uif+rsvd */
      struct {
        u8 uif : 1;
        u8 rsvd : 7;
      };
      u8 pad3;
    };
  } __packed misc;
  u64 upid_addr;
  u64 uirr;
  u64 uitt_addr;
} __packed;

/* xstate management */
int uintr_init_state(struct uintr_process_ctx *ctx);
void uintr_free_state(struct uintr_process_ctx *ctx);

void uintr_save_state(struct uintr_state *state);
void uintr_restore_state(struct uintr_state *state);
void uintr_clear_state(void);

int uintr_alloc_vector(struct uintr_process_ctx *ctx, __u32 vector);
void uintr_free_vector(struct uintr_vector_ctx *vec_ctx);

struct uintr_process_ctx *uintr_create_process_ctx(struct task_struct *task);
void uintr_free_process_ctx(struct uintr_process_ctx *ctx);
#endif
