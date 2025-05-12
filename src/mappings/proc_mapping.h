#ifndef INCLUDE_SRC_PROC_MAPPING_H_
#define INCLUDE_SRC_PROC_MAPPING_H_

#include "../common.h"
#include "../inteldef.h"
#include "../uitt.h"
#include <linux/types.h>

/* Unified process tracking structure */
struct uintr_proc_mapping {
  pid_t pid;
  uintr_process_ctx *ctx;  // For handler, NULL if not a handler
  struct uintr_uitt *uitt; // For sender, NULL if not a sender
  struct hlist_node node;
};

#define UINTR_PROC_BITS 10 /* 1024 buckets */

/* Function to find a process mapping by PID */
struct uintr_proc_mapping *find_proc_mapping(pid_t pid);

/* Function to add or update a handler process mapping */
int add_proc_handler_mapping(pid_t pid, uintr_process_ctx *ctx);

/* Function to add or update a sender process mapping */
int add_proc_sender_mapping(pid_t pid, struct uintr_uitt *uitt);

/* Function to remove a process mapping by PID */
void remove_proc_mapping(pid_t pid);

/* Function to clean up all mappings for a specific handler context */
void remove_all_mappings_for_ctx(uintr_process_ctx *ctx);

/* Function to clean up all mappings for a specific UITT */
void remove_all_mappings_for_uitt(struct uintr_uitt *uitt);

/* Clean up the process mapping subsystem */
void proc_mapping_cleanup(void);

#endif // INCLUDE_SRC_PROC_MAPPING_H_
