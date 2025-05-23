#include "handlers.h"
#include "common.h"
#include "irq.h"
#include "linux/uaccess.h"
#include "logging/monitor.h"
#include "mappings/id_mapping.h"
#include "mappings/proc_mapping.h"
#include "msr.h"
#include "proc.h"
#include "state.h"
#include <asm/io.h>
#include <linux/bits.h>
#include <linux/kthread.h>
#include <linux/slab.h>

uintr_receiver_id_t register_handler(_uintr_handler_args *handler_args) {
  uintr_receiver_id_t id;
  uintr_process_ctx *ctx;
  u64 stack_addr, misc_val;
  int cpu, ret;

  // Verify handler pointer (required)
  if (!handler_args->handler)
    return -EINVAL;

  // Set up stack address (optional)
  if (handler_args->stack) {
    if (!handler_args->stack_size || handler_args->stack_size < PAGE_SIZE) {
      return -EINVAL;
    }

    // handler_args.stack points to the START of allocated buffer (low
    // address) We need to set the stack to the END of the buffer (high
    // address) because stacks grow downward in x86_64
    // Additionally, we must set the lowest bit to 1 to tell the hardware that
    // this the address of the stack to use
    stack_addr = ((u64)handler_args->stack + handler_args->stack_size) | 1;

    pr_debug("UINTR: Stack setup - start: 0x%llx, size: %llu, adjusted top: "
             "0x%llx\n",
             (u64)handler_args->stack, (u64)handler_args->stack_size,
             stack_addr);
  } else {
    stack_addr = OS_ABI_REDZONE * 2;
    pr_debug("UINTR: Using default stack adjustment (OS_ABI_REDZONE * 2): %d\n",
             OS_ABI_REDZONE * 2);
  }

  // Create process context
  // also creates the UPID
  ctx = uintr_create_ctx(current);
  if (!ctx)
    return -ENOMEM;

  // Store handler
  ctx->handler = handler_args->handler;

  preempt_disable();

  if (!ctx->upid) {
    preempt_enable();
    uintr_destroy_ctx(ctx);
    return -EINVAL;
  }

  if (ctx->state.misc.uinv != IRQ_VEC_USER) {
    ctx->state.misc.uinv = IRQ_VEC_USER;
  }

  // Configure MSRs -------
  cpu = smp_processor_id();
  wrmsrl(MSR_IA32_UINTR_HANDLER, (u64)handler_args->handler);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, stack_addr);

  wrmsrl(MSR_IA32_UINTR_PD, (u64)ctx->upid);

  // We need to maintain the state of the reserved bits in the MSR, so we'll
  // read the value, then copy fields UITTSZ and UINV explicitly to this val.
  rdmsrl(MSR_IA32_UINTR_MISC, misc_val);

  // Clear UINV (bits 39:32) and UITTSZ (bits 31:0)
  misc_val &= ~GENMASK_ULL(39, 32);
  misc_val &= ~GENMASK_ULL(31, 0);

  // Set both UINV and UITTSZ
  misc_val |= ((u64)IRQ_VEC_USER << 32);
  misc_val |= (u64)(UINTR_MAX_UVEC_NR - 1);

  // Write misc value back
  wrmsrl(MSR_IA32_UINTR_MISC, misc_val);

  dump_uintr_msrs(NULL);
  pr_debug("UINTR: Registered handler on CPU %d, handler address %lld", cpu,
           (u64)handler_args->handler);

  // register handler scheduler
  ret = add_proc_handler_mapping(ctx->task->pid, ctx);
  if (ret < 0) {
    pr_warn("UINTR: Failed to register process for scheduler tracing: %d\n",
            ret);
  }

  // Save initial state
  ctx->handler_active = true;

  uintr_dump_upid_state(ctx->upid, "register_handler");

  preempt_enable();

  id = generate_receiver_id(ctx);

  ret = add_process_ctx_mapping(id, ctx);
  if (ret < 0) {
    pr_err("UINTR: Failed to assign rec_id %llu to PID %d", id, ctx->task->pid);
  }

  return id;
}

int unregister_handler(uintr_receiver_id_t id) {
  uintr_process_ctx *ctx;

  ctx = find_process_ctx_by_id(id);

  if (ctx) {
    // prevent look up of this ctx by id
    remove_all_recid_mappings_for_ctx(ctx);

    pr_debug("UINTR: Freeing CTX & UPID for PID: %d\n", ctx->task->pid);
    // remove mappings for scheduler tracking of this process
    remove_all_mappings_for_ctx(ctx);
    uintr_destroy_ctx(ctx);
    ctx = NULL;
  }

  return 0;
}
