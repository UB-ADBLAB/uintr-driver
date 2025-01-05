#include "proc.h"
#include "core.h"
#include "state.h"
#include <asm/io.h>
#include <linux/slab.h>

struct uintr_process_ctx *uintr_proc_create(struct task_struct *task) {
  struct uintr_process_ctx *ctx;
  int ret;

  if (!task)
    return NULL;

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx)
    return NULL;

  ctx->task = task;

  ret = uintr_init_state(ctx);
  if (ret < 0) {
    kfree(ctx);
    return NULL;
  }

  return ctx;
}

void uintr_proc_destroy(struct uintr_process_ctx *ctx) {
  struct uintr_vector_ctx *vec, *tmp;

  if (!ctx)
    return;

  // Free all allocated vectors
  list_for_each_entry_safe(vec, tmp, &ctx->vectors, node) {
    list_del(&vec->node);
    uintr_vector_free(vec);
  }

  // Clear CPU state
  uintr_clear_state();

  // Free UPID
  if (ctx->upid) {
    kfree(ctx->upid);
  }

  kfree(ctx);
}

int uintr_alloc_vector(struct uintr_process_ctx *ctx,
                       struct uintr_vector_ctx *vec) {
  if (!ctx || !vec || vec->vector >= UINTR_MAX_UVEC_NR)
    return -EINVAL;

  // Allocate and initialize UITT entry
  vec->uitte = kzalloc(sizeof(struct uintr_uitt_entry), GFP_KERNEL);
  if (!vec->uitte)
    return -ENOMEM;

  vec->uitte->valid = 1;
  vec->uitte->user_vec = vec->vector;
  vec->uitte->target_upid_addr = virt_to_phys(ctx->upid);

  return 0;
}

int uintr_vector_create(struct uintr_process_ctx *proc, __u32 vector) {
  struct uintr_vector_ctx *vec_ctx;
  int ret;

  if (!proc || vector >= UINTR_MAX_UVEC_NR)
    return -EINVAL;

  // Check if vector is already allocated
  spin_lock(&proc->ctx_lock);
  list_for_each_entry(vec_ctx, &proc->vectors, node) {
    if (vec_ctx->vector == vector) {
      spin_unlock(&proc->ctx_lock);
      return -EEXIST;
    }
  }
  spin_unlock(&proc->ctx_lock);

  // Allocate vector context
  vec_ctx = kzalloc(sizeof(*vec_ctx), GFP_KERNEL);
  if (!vec_ctx)
    return -ENOMEM;

  vec_ctx->vector = vector;
  vec_ctx->proc = proc;

  // Allocate UITT entry
  ret = uintr_alloc_vector(proc, vec_ctx);
  if (ret < 0) {
    kfree(vec_ctx);
    return ret;
  }

  // Add to process vector list
  spin_lock(&proc->ctx_lock);
  list_add(&vec_ctx->node, &proc->vectors);
  spin_unlock(&proc->ctx_lock);

  return 0;
}

void uintr_vector_free(struct uintr_vector_ctx *vec) {
  if (!vec)
    return;

  if (vec->uitte) {
    // Clear UITT entry
    vec->uitte->valid = 0;
    vec->uitte->user_vec = 0;
    vec->uitte->target_upid_addr = 0;
  }

  kfree(vec);
}
