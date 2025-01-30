#include "fops.h"
#include "../include/uapi/linux/uintr.h"
#include "core.h"
#include "proc.h"
#include <linux/slab.h>

int register_handler(struct file *file, struct uintr_device *uintr_dev,
                     void __user *arg) {
  struct uintr_handler_args handler_args;
  struct uintr_file *ufile;
  struct uintr_process_ctx *proc;
  u64 handler_addr, stack_addr;
  int ret = 0;

  if (copy_from_user(&handler_args, arg, sizeof(handler_args)))
    return -EFAULT;

  if (!handler_args.handler)
    return -EINVAL;

  // If stack specified, validate stack parameters
  if (handler_args.stack) {
    if (!handler_args.stack_size || handler_args.stack_size < PAGE_SIZE)
      return -EINVAL;
    stack_addr = (u64)handler_args.stack + handler_args.stack_size;
  } else {
    stack_addr = 0; // Use default kernel stack
  }

  ufile = kzalloc(sizeof(*ufile), GFP_KERNEL);
  if (!ufile)
    return -ENOMEM;

  // Create process context
  proc = uintr_proc_create(current);
  if (!proc) {
    ret = -ENOMEM;
    goto err_free_ufile;
  }

  ufile->proc->handler = handler_args.handler;
  wrmsrl(MSR_IA32_UINTR_PD, virt_to_phys(ufile->proc->upid));
  wrmsrl(MSR_IA32_UINTR_HANDLER, (u64)handler_args.handler);

  proc->handler = handler_args.handler;
  ufile->proc = proc;

  // Initialize file structure
  spin_lock_init(&ufile->file_lock);
  ufile->uintr_dev = uintr_dev;
  file->private_data = ufile;

  // Convert user virtual address to physical for MSR
  handler_addr = (u64)handler_args.handler;

  // Program MSRs for this CPU
  preempt_disable();

  // Set handler address
  wrmsrl(MSR_IA32_UINTR_HANDLER, handler_addr);

  // Set stack adjustment if custom stack provided
  if (stack_addr)
    wrmsrl(MSR_IA32_UINTR_STACKADJUST, stack_addr);

  // Set UPID physical address
  wrmsrl(MSR_IA32_UINTR_PD, virt_to_phys(proc->upid));

  // Initialize MISC MSR:
  // - UITT size (8 bits for 256 entries)
  // - Clear UINV (user interrupt notification valid)
  // - Clear UIF (user interrupt flag)
  wrmsrl(MSR_IA32_UINTR_MISC, (u64)8 << 32);

  // Save initial state
  uintr_save_state(&proc->state);
  proc->handler_active = true;

  preempt_enable();

  return 0;

err_free_ufile:
  kfree(ufile);
  return ret;
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

  ret = uintr_vector_create(ufile->proc, vector_args.vector);
  if (ret < 0)
    return ret;

  return 0;
}

int unregister_handler(struct file *file) {
  struct uintr_file *ufile = file->private_data;

  if (!ufile)
    return -EINVAL;

  if (ufile->proc) {
    uintr_proc_destroy(ufile->proc);
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
    ret = register_handler(file, uintr_dev, (void __user *)arg);
    break;
  case UINTR_CREATE_FD:
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
  struct uintr_file *ufile = file->private_data;

  if (ufile) {
    if (ufile->proc) {
      uintr_proc_destroy(ufile->proc);
    }
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
