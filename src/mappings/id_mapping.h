#ifndef INCLUDE_SRC_ID_MAPPING_H_
#define INCLUDE_SRC_ID_MAPPING_H_

#include "../common.h"
#include "../inteldef.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct receiver_id_mapping {
  uintr_receiver_id_t id;
  uintr_process_ctx *ctx;
  struct hlist_node node;
};

#define RECEIVER_ID_BITS 10 // 2^10 buckets

// Function to find a context by ID
uintr_process_ctx *find_process_ctx_by_id(uintr_receiver_id_t id);

// Function to add a new mapping
int add_process_ctx_mapping(uintr_receiver_id_t id, uintr_process_ctx *ctx);

// Function to remove a mapping
void remove_process_ctx_mapping(uintr_receiver_id_t id);

// Function to clean up all mappings for a specific context
void remove_all_mappings_for_ctx(uintr_process_ctx *ctx);

#endif // INCLUDE_SRC_ID_MAPPING_H_
