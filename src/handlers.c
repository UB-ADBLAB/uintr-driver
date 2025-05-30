#include "handlers.h"
#include "asm.h"
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
  unsigned long flags;

  // Verify handler pointer (required)
  if (!handler_args->handler)
    return -EINVAL;

  // Set up stack address (optional)
  if (handler_args->stack) {
    if (!handler_args->stack_size || handler_args->stack_size < PAGE_SIZE) {
      return -EINVAL;
    }

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

  // Find existing context or create new one
  ctx = find_process_ctx(current->pid);
  if (!ctx) {
    ctx = uintr_create_ctx(current);
    if (!ctx)
      return -ENOMEM;

    // Add to process mapping
    ret = add_process_mapping(current->pid, ctx);
    if (ret < 0) {
      uintr_destroy_ctx(ctx);
      return ret;
    }
  }

  /* Lock context during setup */
  spin_lock_irqsave(&ctx->ctx_lock, flags);

  // Update role
  ctx->role |= UINTR_RECEIVER;

  // Store handler state
  ctx->handler = handler_args->handler;

  preempt_disable();

  if (!ctx->upid) {
    // Create UPID if needed
    ret = uintr_create_upid(ctx);
    if (ret < 0) {
      spin_unlock_irqrestore(&ctx->ctx_lock, flags);
      preempt_enable();
      if (ctx->role == UINTR_RECEIVER) {
        // If this was the only role, remove the context
        remove_process_mapping(current->pid);
        uintr_destroy_ctx(ctx);
      }
      return -EINVAL;
    }
  }

  if (ctx->state.misc.uinv != IRQ_VEC_USER) {
    ctx->state.misc.uinv = IRQ_VEC_USER;
  }

  // Configure MSRs -------
  cpu = smp_processor_id();
  wrmsrl(MSR_IA32_UINTR_HANDLER, (u64)handler_args->handler);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, stack_addr);
  wrmsrl(MSR_IA32_UINTR_PD, (u64)ctx->upid);

  // We need to maintain the state of the reserved bits in the MSR
  rdmsrl(MSR_IA32_UINTR_MISC, misc_val);
  misc_val &= ~GENMASK_ULL(39, 32);
  misc_val &= ~GENMASK_ULL(31, 0);
  misc_val |= ((u64)IRQ_VEC_USER << 32);
  misc_val |= (u64)(UINTR_MAX_UVEC_NR - 1);
  wrmsrl(MSR_IA32_UINTR_MISC, misc_val);

  /* Memory barrier to ensure MSRs are configured before enabling */
  smp_wmb();

  // Update state structure with current MSR values
  ctx->state.handler = (u64)handler_args->handler;
  ctx->state.stack_adjust = stack_addr;
  ctx->state.upid_addr = (u64)ctx->upid;
  ctx->state.misc.uinv = IRQ_VEC_USER;

  spin_unlock_irqrestore(&ctx->ctx_lock, flags);

  dump_uintr_msrs(NULL);
  pr_debug("UINTR: Registered handler on CPU %d, handler address %lld", cpu,
           (u64)handler_args->handler);

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
  unsigned long flags;

  ctx = find_process_ctx_by_id(id);
  if (!ctx)
    return -EINVAL;

  // If this is the current process, clear MSRs immediately
  if (current->pid == ctx->task->pid) {
    pr_debug("UINTR: Clearing MSRs for current process during unregister\n");
    __clui(); // Disable interrupts first
    preempt_disable();

    // Clear only receiver-related MSRs if process is also a sender
    if (ctx->role == UINTR_BOTH) {
      wrmsrl(MSR_IA32_UINTR_HANDLER, 0);
      wrmsrl(MSR_IA32_UINTR_STACKADJUST, 0);
      wrmsrl(MSR_IA32_UINTR_PD, 0);
      wrmsrl(MSR_IA32_UINTR_RR, 0);
      // Keep TT MSR for sender functionality
    } else {
      uintr_clear_state(NULL);
    }

    preempt_enable();
  }

  spin_lock_irqsave(&ctx->ctx_lock, flags);

  // Update role
  ctx->role &= ~UINTR_RECEIVER;

  // Clear receiver state
  ctx->handler = NULL;

  // Free UPID
  if (ctx->upid) {
    // Set suppress notification bit to prevent further interrupts
    set_bit(UINTR_UPID_STATUS_SN, (unsigned long *)&ctx->upid->nc.status);
    smp_wmb();

    kfree(ctx->upid);
    ctx->upid = NULL;
  }

  spin_unlock_irqrestore(&ctx->ctx_lock, flags);

  // prevent look up of this ctx by id
  remove_all_recid_mappings_for_ctx(ctx);

  // If process has no more roles, clean up completely
  if (ctx->role == UINTR_NONE) {
    pr_debug("UINTR: Process has no more roles, cleaning up completely for "
             "PID: %d\n",
             ctx->task->pid);
    remove_process_mapping(ctx->task->pid);
    uintr_destroy_ctx(ctx);
  }

  return 0;
}
