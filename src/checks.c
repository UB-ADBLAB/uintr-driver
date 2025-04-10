#include "checks.h"
#include "common.h"

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
  u64 xss_val;

  /* Verify Intel CPU */
  if (c->x86_vendor != X86_VENDOR_INTEL) {
    pr_err("UINTR: Not an Intel CPU\n");
    return -EINVAL;
  }

  /* Verify UINTR support */
  if (!cpu_have_feature(X86_FEATURE_UINTR)) {
    pr_err("UINTR: CPU does not support user interrupts\n");
    return -EINVAL;
  }

  /* Verify XSAVE UINTR feature support */
  if (!cpu_have_feature(X86_FEATURE_XSAVE) &&
      !cpu_have_feature(X86_FEATURE_XSAVES)) {
    pr_warn("UINTR: CPU does not support XSAVE\n");
  } else {
    /* check that we actually have uintr xsave support */
    rdmsrl(MSR_IA32_XSS, xss_val);

    if (!(xss_val & (1ULL << XFEATURE_UINTR))) {
      pr_warn("UINTR: CPU does not support XSAVE for user interrupts\n");
      // TODO: set flag to use backup state management (current implementation)
    }
  }

  pr_info("UINTR: Compatible CPU detected (Family: %d, Model: %x)\n", c->x86,
          c->x86_model);
  // pr_info("UINTR: CR4: 0x%lx\n", __read_cr4());

  return 0;
}
