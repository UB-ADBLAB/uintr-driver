#ifndef INCLUDE_SRC_PROC_MAPPING_H_
#define INCLUDE_SRC_PROC_MAPPING_H_

#include "../common.h"
#include "../inteldef.h"
#include <linux/types.h>

// mapping data structure
struct uintr_proc_mapping {
  pid_t pid;
  uintr_process_ctx *ctx;
  struct hlist_node node;
};

#define UINTR_PROC_BITS 10 /* 1024 buckets */

uintr_process_ctx *find_process_ctx(pid_t pid);

int add_process_mapping(pid_t pid, uintr_process_ctx *ctx);

void remove_process_mapping(pid_t pid);

void remove_all_mappings_for_ctx(uintr_process_ctx *ctx);

void proc_mapping_cleanup(void);

#endif // INCLUDE_SRC_PROC_MAPPING_H_
