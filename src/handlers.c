#include "handlers.h"
#include "common.h"
#include "irq.h"
#include "linux/uaccess.h"
#include "logging/monitor.h"
#include "mappings/id_mapping.h"
#include "msr.h"
#include "proc.h"
#include "state.h"
#include "trace/sched.h"
#include <asm/io.h>
#include <linux/bits.h>
#include <linux/kthread.h>
#include <linux/slab.h>

uintr_receiver_id_t register_handler(struct _uintr_handler_args *handler_args) {
  uintr_receiver_id_t id;
  uintr_process_ctx *ctx;
  u64 stack_addr, misc_val;
  int cpu, ret;

  // verify handler args
  if (!handler_args->handler)
    return -EINVAL;

  // Set up stack address
  if (handler_args->stack) {
    if (!handler_args->stack_size || handler_args->stack_size < PAGE_SIZE) {
      return -EINVAL;
    }

    // handler_args.stack points to the START of allocated buffer (low address)
    // We need to set the stack to the END of the buffer (high address)
    // because stacks grow downward in x86_64
    stack_addr = (u64)handler_args->stack + handler_args->stack_size;

    pr_info("UINTR: Stack setup - start: 0x%llx, size: %llu, adjusted top: "
            "0x%llx\n",
            (u64)handler_args->stack, (u64)handler_args->stack_size,
            stack_addr);
  } else {
    stack_addr = OS_ABI_REDZONE;
    pr_info("UINTR: Using default stack adjustment (red zone): %d\n",
            OS_ABI_REDZONE);
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
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, stack_addr | 0x1);
  // lowest bit indicates this reg is set ---------^

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
  pr_info("UINTR: Registered handler on CPU %d, handler address %lld", cpu,
          (u64)handler_args->handler);

  // register handler scheduler
  ret = uintr_sched_trace_register_proc(ctx);
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
  // TODO: must also remove all uitt that was associated
  if (ctx) {
    uintr_destroy_ctx(ctx);
  }

  return 0;
}
