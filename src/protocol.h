#ifndef _UINTR_PROTOCOL_H
#define _UINTR_PROTOCOL_H

#include <linux/types.h>

// TODO: These values should be calculated (?)
// Intel SDM Vol. 2B 4-616
#define UINTR_MAX_UVEC_NR 64
#define UINTR_MAX_UITT_NR 256

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
    u32 ndst;
  } __packed nc;
  u64 puir;
} __aligned(64);

struct uintr_uitt_entry {
  u8 valid;
  u8 user_vec;
  u8 reserved[6];
  u64 target_upid_addr;
} __packed __aligned(16);

#endif
