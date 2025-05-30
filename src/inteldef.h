#ifndef _UINTR_TYPES_H
#define _UINTR_TYPES_H

#include "common.h"
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

// MSRs as specified in Intel SDM
#define MSR_IA32_UINTR_RR 0x985
#define MSR_IA32_UINTR_HANDLER 0x986
#define MSR_IA32_UINTR_STACKADJUST 0x987
#define MSR_IA32_UINTR_MISC 0x988
#define MSR_IA32_UINTR_PD 0x989
#define MSR_IA32_UINTR_TT 0x98a

#define X86_FEATURE_UINTR (18 * 32 + 5) /* User Interrupts support */

#ifndef X86_CR4_UINTR
#define X86_CR4_UINTR (1ULL << 25) /* CR4 bit */
#endif

#define UINTR_MAX_UVEC_NR 64

// UPID Notification control status bits
#define UINTR_UPID_STATUS_ON 0x0
#define UINTR_UPID_STATUS_SN 0x1
#define UINTR_UPID_STATUS_BLKD 0x7

// See Intel SDM Vol. 2B 4-616
struct uintr_upid {
  struct {
    u8 status;
    u8 reserved1;
    u8 nv;
    u8 reserved2;
    u32 ndst; // refers to the physical destination to send this interrupt
  } __packed nc;
  u64 puir;
} __aligned(64);

// MSR state that gets saved/restored on context switch
struct uintr_state {
  u64 handler;
  u64 stack_adjust;
  struct {
    u32 uitt_size;
    u8 uinv;
    u8 pad1;
    u8 pad2;
    union {
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

// Role types
typedef enum {
  UINTR_NONE = 0,
  UINTR_RECEIVER = 1,
  UINTR_SENDER = 2,
  UINTR_BOTH = 3
} uintr_role_t;

// Unified process context
typedef struct {
  struct task_struct *task;
  uintr_role_t role;

  // MSR snapshot for context switching
  struct uintr_state state;

  // Receiver-specific state (only valid if role & UINTR_RECEIVER)
  void *handler;
  struct uintr_upid *upid;

  // Sender-specific state (only valid if role & UINTR_SENDER)
  struct uintr_uitt *uitt;

  spinlock_t ctx_lock;
} uintr_process_ctx;

#endif
