#include "fops.h"
#include "core.h"
#include "../include/uapi/linux/uintr.h"
#include <linux/slab.h>
#include "proc.h"

int register_handler(struct file *file, struct uintr_device *uintr_dev, void __user *arg) {
  struct uintr_handler_args handler_args;
  struct uintr_file *ufile;
  int ret = 0;

  if (copy_from_user(&handler_args, arg, sizeof(handler_args)))
    return -EFAULT;

  ufile = kzalloc(sizeof(*ufile), GFP_KERNEL);
  if (!ufile)
    return -ENOMEM;

  // Create process context
  ufile->proc = uintr_proc_create(current);
  if (!ufile->proc) {
    kfree(ufile);
    return -ENOMEM;
  }

  ufile->proc->handler = handler_args.handler;
  
  // Initialize file structure
  spin_lock_init(&ufile->file_lock);
  ufile->uintr_dev = uintr_dev;
 file->private_data = ufile;


  return ret;
}

int create_vector(struct file *file, struct uintr_device *uintr_dev, void __user *arg) {
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

long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
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

int uintr_open(struct inode *inode, struct file *file)
{
    struct uintr_device *uintr_dev = container_of(file->private_data,
                                                 struct uintr_device,
                                                 misc);
    
    file->private_data = uintr_dev;
    
    return 0;
}

int uintr_release(struct inode *inode, struct file *file)
{
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
