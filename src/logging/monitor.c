#include "monitor.h"
#include "../state.h"
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/kthread.h>

static inline bool debug_enabled(void) {
  return IS_ENABLED(CONFIG_DYNAMIC_DEBUG);
}

void uintr_dump_upid_state(const struct uintr_upid *upid, const char *caller) {
  if (!upid) {
    pr_warn("UINTR [%s]: UPID is NULL\n", caller);
    return;
  }
  if (!debug_enabled())
    return;

  pr_debug("UINTR [%s]: UPID State (addr %px):\n", caller, upid);
  pr_debug("  Raw memory (64 bytes):");
  print_hex_dump_debug("    ", DUMP_PREFIX_OFFSET, 16, 1, upid,
                       sizeof(struct uintr_upid), true);

  pr_debug("  Status: %s (0x%x)\n", get_status_str(upid->nc.status),
           upid->nc.status);
  pr_debug("  Notification Vector: 0x%x\n", upid->nc.nv);
  pr_debug("  Notification Dest: 0x%x\n", upid->nc.ndst);
  pr_debug("  Posted Interrupts: 0x%llx\n", upid->puir);
}

char *get_status_str(u8 status) {
  if (status & (1 << UINTR_UPID_STATUS_BLKD))
    return "BLKD";
  if (status & (1 << UINTR_UPID_STATUS_SN))
    return "SN";
  if (status & (1 << UINTR_UPID_STATUS_ON))
    return "ON";
  return "OFF";
}
