#ifndef INCLUDE_MAPPINGS_UITT_MAPPING_H_
#define INCLUDE_MAPPINGS_UITT_MAPPING_H_

#include "../uitt.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define UITT_PID_BITS 10 /* 2^10 buckets */

struct uitt_mapping {
  pid_t pid;
  struct uintr_uitt *uitt;
  struct hlist_node node;
};

struct uintr_uitt *find_uitt_by_pid(pid_t pid);

int add_uitt_mapping(pid_t pid, struct uintr_uitt *uitt);

void remove_uitt_mapping(pid_t pid);

void remove_all_mappings_for_uitt(struct uintr_uitt *uitt);

#endif // INCLUDE_MAPPINGS_UITT_MAPPING_H_
