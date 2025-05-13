#ifndef _UINTR_FOPS_H
#define _UINTR_FOPS_H

#include "driver.h"
#include "inteldef.h"
#include <linux/fs.h>

int uintr_open(struct inode *inode, struct file *file);
int uintr_release(struct inode *inode, struct file *file);
long uintr_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

extern const struct file_operations uintr_fops;

#endif
