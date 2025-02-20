#include "fops.h"
#include "../include/uapi/linux/uintr.h"
#include "core.h"
#include "logging/monitor.h"
#include "proc.h"
#include "uitt.h"
#include <asm/io.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#define OS_ABI_REDZONE 128

struct uintr_process_ctx *register_handler(struct file *file,
                                           struct uintr_device *uintr_dev,
                                           void __user *arg) {
  struct uintr_handler_args handler_args;
  struct uintr_process_ctx *proc;
  u64 stack_addr;
  int cpu;

  if (copy_from_user(&handler_args, arg, sizeof(handler_args)))
    return ERR_PTR(-EFAULT);

  if (!handler_args.handler)
    return ERR_PTR(-EINVAL);

  // Create process context
  proc = uintr_proc_create(current);
  if (!proc)
    return ERR_PTR(-ENOMEM);

  // Set up stack address
  if (handler_args.stack) {
    if (!handler_args.stack_size || handler_args.stack_size < PAGE_SIZE) {
      uintr_proc_destroy(proc);
      return ERR_PTR(-EINVAL);
    }
    stack_addr = (u64)handler_args.stack + handler_args.stack_size;
  } else {
    stack_addr = OS_ABI_REDZONE;
  }

  atomic_set(&monitor_should_exit, 0);
  monitor_task = kthread_run(upid_monitor_thread, proc, "uintr_monitor");
  if (IS_ERR(monitor_task)) {
    pr_err("UINTR: Failed to create monitor thread\n");
    monitor_task = NULL;
  }

  // Store handler
  proc->handler = handler_args.handler;

  // Store process context directly in file
  file->private_data = proc;

  preempt_disable();

  if (!proc->upid) {
    preempt_enable();
    uintr_proc_destroy(proc);
    return ERR_PTR(-EINVAL);
  }

  // Configure MSRs

  cpu = smp_processor_id();
  wrmsrl(MSR_IA32_UINTR_HANDLER, (u64)handler_args.handler);
  wrmsrl(MSR_IA32_UINTR_STACKADJUST, stack_addr);
  wrmsrl(MSR_IA32_UINTR_PD, (u64)proc->upid); // virt_to_phys?
  wrmsrl(MSR_IA32_UINTR_MISC, (u64)8 << 32);

  pr_info("UINTR: Registered handler on CPU %d, handler address %lld", cpu,
          (u64)handler_args.handler);

  if (cpu_physical_id(cpu) != proc->upid->nc.ndst)

    // Save initial state
    proc->handler_active = true;

  uintr_dump_upid_state(proc->upid, "register_handler");

  preempt_enable();

  return proc;
}

int create_vector(struct file *file, struct uintr_device *uintr_dev,
                  void __user *arg) {
  struct uintr_vector_args vector_args;
  struct uintr_file *ufile;
  int ret;

  if (copy_from_user(&vector_args, arg, sizeof(vector_args)))
    return -EFAULT;

  ufile = file->private_data;
  if (!ufile || !ufile->proc)
    return -EINVAL;

  // TODO: I have chosen to simplify the process of creating vectors, so we'll
  // have to come back to this.
  ret = 0; // uintr_vector_create(ufile->proc, vector_args.vector);
  if (ret < 0)
    return ret;

  return 0;
}

int unregister_handler(struct file *file) {
  struct uintr_file *ufile = file->private_data;
  struct uintr_process_ctx *ctx;

  if (!ufile) {
    pr_warn("UINTR: unregister_handler called with NULL ufile\n");
    return -EINVAL;
  }

  ctx = ufile->proc;
  if (ctx) {
    // Stop monitoring thread first
    if (monitor_task) {
      atomic_set(&monitor_should_exit, 1);
      kthread_stop(monitor_task);
      monitor_task = NULL;
    }

    ctx->task = NULL;

    smp_wmb();

    uintr_proc_destroy(ctx);
    ufile->proc = NULL;
  }

  kfree(ufile);
  file->private_data = NULL;

  return 0;
}

long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  struct uintr_device *uintr_dev = file->private_data;
  int ret = 0;

  switch (cmd) {
  case UINTR_REGISTER_HANDLER:
    struct uintr_process_ctx *ctx =
        register_handler(file, uintr_dev, (void __user *)arg);
    ret = uitt_alloc_entry(ctx);
    break;
  case UINTR_CREATE_FD:
    pr_info("UINTR: IOCTL reached.");
    ret = create_vector(file, uintr_dev, (void __user *)arg);
    break;
  case UINTR_UNREGISTER_HANDLER:
    ret = unregister_handler(file);
    break;
  default:
    ret = -EINVAL;
  }

  return ret;
}

int uintr_open(struct inode *inode, struct file *file) {
  struct uintr_device *uintr_dev =
      container_of(file->private_data, struct uintr_device, misc);

  file->private_data = uintr_dev;

  return 0;
}

int uintr_release(struct inode *inode, struct file *file) {
  struct uintr_process_ctx *proc = file->private_data;

  if (proc) {
    uintr_proc_destroy(proc);
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
