#ifndef _UINTR_STATE_H
#define _UINTR_STATE_H

#include <linux/types.h>

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
    union { /* byte 23 = pad3/uif+rsvd */
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

#endif
