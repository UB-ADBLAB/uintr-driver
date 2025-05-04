#include "fops.h"
#include "asm/special_insns.h"
#include "common.h"
#include "inteldef.h"
#include "irq.h"
#include "linux/smp.h"
#include "linux/spinlock.h"
#include "logging/monitor.h"
#include "msr.h"
#include "proc.h"
#include "state.h"
#include "trace/sched.h"
#include "uitt.h"
#include <asm/io.h>
#include <linux/bits.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#define OS_ABI_REDZONE 128

extern struct uintr_uitt_manager *uitt_mgr;

struct uintr_process_ctx *register_handler(struct file *file,
                                           struct uintr_device *uintr_dev,
                                           void __user *arg) {
  struct _uintr_handler_args handler_args;
  struct uintr_process_ctx *proc;
  u64 stack_addr, misc_val;
  int cpu, ret;

  // set up handler_args in kernel space
  if (copy_from_user(&handler_args, arg, sizeof(handler_args)))
    return ERR_PTR(-EFAULT);

  if (!handler_args.handler)
    return ERR_PTR(-EINVAL);

  // Set up stack address
  if (handler_args.stack) {
    if (!handler_args.stack_size || handler_args.stack_size < PAGE_SIZE) {
      return ERR_PTR(-EINVAL);
    }

    // handler_args.stack points to the START of allocated buffer (low address)
    // We need to set the stack to the END of the buffer (high address)
    // because stacks grow downward in x86_64
    stack_addr = (u64)handler_args.stack + handler_args.stack_size;

    pr_info("UINTR: Stack setup - start: 0x%llx, size: %llu, adjusted top: "
            "0x%llx\n",
            (u64)handler_args.stack, (u64)handler_args.stack_size, stack_addr);
  } else {
    stack_addr = OS_ABI_REDZONE;
    pr_info("UINTR: Using default stack adjustment (red zone): %d\n",
            OS_ABI_REDZONE);
  }

  // Create process context
  proc = uintr_proc_create(current, uintr_dev);
  if (!proc)
    return ERR_PTR(-ENOMEM);

  // Store handler
  proc->handler = handler_args.handler;

  preempt_disable();

  if (!proc->upid) {
    preempt_enable();
    uintr_proc_destroy(proc);
    return ERR_PTR(-EINVAL);
  }

  if (proc->state.misc.uinv != IRQ_VEC_USER) {
    proc->state.misc.uinv = IRQ_VEC_USER;
  }

  // Configure MSRs

  cpu = smp_processor_id();
  wrmsrl(MSR_IA32_UINTR_HANDLER, (u64)handler_args.handler);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, stack_addr | 0x1);
  // lowest bit indicates this reg is set ---------^

  wrmsrl(MSR_IA32_UINTR_PD, (u64)proc->upid);

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
          (u64)handler_args.handler);

  // register handler scheduler
  ret = uintr_sched_trace_register_proc(proc);
  if (ret < 0) {
    pr_warn("UINTR: Failed to register process for scheduler tracing: %d\n",
            ret);
  }

  // Save initial state
  proc->handler_active = true;

  uintr_dump_upid_state(proc->upid, "register_handler");
  uintr_dump_uitt_state("register_handler");

  preempt_enable();

  return proc;
}

int unregister_handler(unsigned int uitte_idx) {
  struct uintr_process_ctx *ctx;

  ctx = uitt_get_proc_ctx(uitte_idx);
  if (!ctx) {
    pr_warn("UINTR: No process context found for UITT index %u\n", uitte_idx);
    return -EINVAL;
  }

  uitt_free_entry(uitte_idx);

  uintr_proc_destroy(ctx);

  uitt_set_proc_ctx(uitte_idx, NULL);

  return 0;
}

long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  struct uintr_file *ufile = file->private_data;
  struct uintr_device *uintr_dev = ufile->uintr_dev;
  unsigned long flags;
  int ret = 0;

  if (!ufile) {
    pr_err("UINTR: Invalid private_data in uintr_ioctl\n");
  }

  spin_lock_irqsave(&ufile->file_lock, flags);

  switch (cmd) {
  case UINTR_REGISTER_HANDLER: {
    struct uintr_process_ctx *ctx = NULL;
    ctx = register_handler(file, uintr_dev, (void __user *)arg);
    if (ctx) {
      ret = uitt_alloc_entry(ctx);
    } else {
      ret = -1;
      pr_warn("UINTR: register_handler returned NULL!\n");
    }
    break;
  }
  case UINTR_UNREGISTER_HANDLER: {
    unsigned int idx = (unsigned int)arg;
    ret = unregister_handler(idx);
    break;
  }
  case UINTR_DUMP_ENTRY: {
    unsigned int idx = (unsigned int)arg;
    pr_info(
        "UINTR DEBUG:\n#############  dumping uitt entry: %d  ##############\n",
        idx);
    uintr_dump_uitt_entry_state(&uitt_mgr->uitt->entries[idx], idx,
                                "UINTR_DEBUG");
    break;
  }
  case UINTR_DUMP_MSR: {
    int cpu = (int)arg;
    pr_info("UINTR DEBUG:\n#############  dumping msrs for  ##############\n"
            "#############  cpu: %d, apic: %d  ##############",
            cpu, cpu_to_ndst(cpu));
    smp_call_function_single(cpu, dump_uintr_msrs, NULL, 1);
    break;
  }
  default:
    ret = -EINVAL;
  }

  spin_unlock_irqrestore(&ufile->file_lock, flags);

  return ret;
}

int uintr_open(struct inode *inode, struct file *file) {
  struct uintr_file *ufile = kzalloc(sizeof(*ufile), GFP_KERNEL);
  if (!ufile)
    return -ENOMEM;

  ufile->uintr_dev =
      container_of(file->private_data, struct uintr_device, misc);
  spin_lock_init(&ufile->file_lock);
  file->private_data = ufile;

  pr_info("UINTR: Opened device file, created ufile %p\n", ufile);
  return 0;
}

int uintr_release(struct inode *inode, struct file *file) {
  struct uintr_file *ufile = file->private_data;

  pr_info("UINTR: Releasing device file, ufile %p\n", ufile);

  if (ufile) {
    kfree(ufile);
    file->private_data = NULL;
  }

  return 0;
}

const struct file_operations uintr_fops = {
    .owner = THIS_MODULE,
    .open = uintr_open,
    .release = uintr_release,
    .unlocked_ioctl = uintr_ioctl,
};
