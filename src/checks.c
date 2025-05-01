#include "checks.h"
#include "inteldef.h"

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>

/*
 * check_cpu_compatibility - Verify CPU supports UINTR feature
 *
 * Returns 0 if CPU is compatible, negative error code otherwise
 */
int check_cpu_compatibility(void) {
  struct cpuinfo_x86 *c = &cpu_data(0);

  /* Verify Intel CPU */
  if (c->x86_vendor != X86_VENDOR_INTEL) {
    pr_err("UINTR: Cannot load driver, not an Intel CPU\n");
    return -EINVAL;
  }

  /* Verify UINTR support */
  if (!cpu_have_feature(X86_FEATURE_UINTR)) {
    pr_err("UINTR: CPU does not support user interrupts\n");
    return -EINVAL;
  }

  pr_info("UINTR: Compatible CPU detected (Family: %d, Model: %x)\n", c->x86,
          c->x86_model);

  return 0;
}
