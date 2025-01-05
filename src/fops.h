#ifndef _UINTR_FOPS_H
#define _UINTR_FOPS_H

#include <linux/fs.h>
#include "core.h"

int uintr_open(struct inode *inode, struct file *file);
int uintr_release(struct inode *inode, struct file *file);
long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

int register_handler(struct file *file, struct uintr_device *uintr_dev, void __user *arg);
int create_vector(struct file *file, struct uintr_device *uintr_dev, void __user *arg);
int unregister_handler(struct file *file);

extern const struct file_operations uintr_fops;

#endif