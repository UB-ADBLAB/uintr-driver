#include "fops.h"
#include "asm/special_insns.h"
#include "common.h"
#include "handlers.h"
#include "inteldef.h"
#include "irq.h"
#include "linux/smp.h"
#include "linux/spinlock.h"
#include "logging/monitor.h"
#include "mappings/proc_mapping.h"
#include "msr.h"
#include "proc.h"
#include "state.h"
#include "trace/sched.h"
#include "uitt.h"
#include <asm/io.h>
#include <linux/bits.h>
#include <linux/kthread.h>
#include <linux/slab.h>

long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  struct uintr_file *ufile = file->private_data;
  unsigned long flags;
  int ret = 0;

  if (!ufile) {
    pr_err("UINTR: Invalid private_data in uintr_ioctl\n");
  }

  spin_lock_irqsave(&ufile->file_lock, flags);

  switch (cmd) {
  case UINTR_REGISTER_HANDLER: {
    _uintr_handler_args handler_args;

    if (copy_from_user(&handler_args, (void __user *)arg,
                       sizeof(handler_args))) {
      ret = -EFAULT;
      break;
    }

    ret = register_handler(&handler_args);
    break;
  }
  case UINTR_UNREGISTER_HANDLER: {
    uintr_receiver_id_t idx = arg;
    ret = unregister_handler(idx);
    break;
  }
  case UINTR_REGISTER_SENDER: {
    _uintr_sender_args sender_args;
    if (copy_from_user(&sender_args, (void __user *)arg, sizeof(sender_args)))
      return -EFAULT;
    ret = register_sender(sender_args.receiver_id, sender_args.vector);
    break;
  }
  case UINTR_UNREGISTER_SENDER: {
    int idx = (int)arg;
    // ret = unregister_sender(idx);
    break;
  }
  case UINTR_DEBUG: {
    dump_uintr_msrs(NULL);
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
