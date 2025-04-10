#ifndef _UINTR_FOPS_H
#define _UINTR_FOPS_H

#include "common.h"
#include "driver.h"
#include <linux/fs.h>

int uintr_open(struct inode *inode, struct file *file);
int uintr_release(struct inode *inode, struct file *file);
long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

struct uintr_process_ctx *register_handler(struct file *file,
                                           struct uintr_device *uintr_dev,
                                           void __user *arg);

int unregister_handler(unsigned int uitte_idx);

extern const struct file_operations uintr_fops;

#endif
