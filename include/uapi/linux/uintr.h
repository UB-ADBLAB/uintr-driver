#ifndef _UAPI_ASM_X86_UINTR_H
#define _UAPI_ASM_X86_UINTR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../../../src/common.h"

#include <fcntl.h>
#include <linux/types.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// structure to hold thread local state for UINTR
typedef struct {
  int dev_fd;
  int uipi_index; // the index returned by the real register ioctl
  void *handler_stack;
  size_t stack_size;
  int registered; // flag indicating if handler is registered in this thread yet
} _uintr_thread_context_t;

// the thread-local storage variable (actually defined in database uintr.cc)
extern thread_local _uintr_thread_context_t _uintr_tls_context;

/*
 * helper that sets the stack details in TLS for the *next* call to
 * uintr_register_handler.
 */
static inline int uintr_set_thread_stack_info(void *stack, size_t stack_size) {
  if (!stack ||
      stack_size < sysconf(_SC_PAGESIZE)) { // Use sysconf for page size
    fprintf(stderr, "[UINTR SHIM] Invalid stack pointer (%p) or size (%zu)\n",
            stack, stack_size);
    return -EINVAL;
  }
  _uintr_tls_context.handler_stack = stack;
  _uintr_tls_context.stack_size = stack_size;
  return 0;
}

/*
 * registers the UINTR handler using ioctl.
 * IMPORTANT: uintr_set_thread_stack_info() must be called before this function
 * to provide the necessary stack details.
 */
static inline long uintr_register_handler(void *handler, unsigned int flags) {
  _uintr_thread_context_t *ctx = &_uintr_tls_context;

  if (ctx->registered) {
    fprintf(stderr,
            "[UINTR SHIM] Handler already registered in this thread.\n");
    return -EALREADY;
  }

  // check if stack info was provided via helper
  if (!ctx->handler_stack || ctx->stack_size == 0) {
    fprintf(stderr,
            "[UINTR SHIM] Stack info not set via uintr_set_thread_stack_info() "
            "before calling uintr_register_handler.\n");
    return -EINVAL;
  }

  // open the device for ioctl
  ctx->dev_fd = open("/dev/uintr", O_RDWR);
  if (ctx->dev_fd < 0) {
    perror("[UINTR SHIM] Failed to open /dev/uintr");
    return -errno;
  }

  struct _uintr_handler_args args = {0};
  args.handler = handler;
  args.stack = (void *)((char *)ctx->handler_stack + ctx->stack_size);
  args.stack_size = ctx->stack_size;
  args.flags = flags;

  // call the real register handler ioctl
  long ret = ioctl(ctx->dev_fd, UINTR_REGISTER_HANDLER, &args);
  if (ret < 0) {
    int saved_errno = errno;
    perror("[UINTR SHIM] UINTR_REGISTER_HANDLER ioctl failed");
    close(ctx->dev_fd);
    ctx->dev_fd = -1;
    // clear stack info from TLS as registration failed
    ctx->handler_stack = NULL;
    ctx->stack_size = 0;
    return -saved_errno;
  }

  // success: store index and mark registered
  ctx->uipi_index = (int)ret;
  ctx->registered = 1;

  // return 0 as the original syscall intended
  return 0;
}

/*
 * unregisters the UINTR handler using the driver's ioctl.
 * cleans up TLS state and closes the device FD.
 * flags currently ignored
 */
static inline long uintr_unregister_handler(unsigned int flags) {
  _uintr_thread_context_t *ctx = &_uintr_tls_context;

  if (!ctx->registered) {
    fprintf(stderr, "[UINTR SHIM] Warning - Attempting to unregister handler "
                    "but none registered in this thread.\n");
    return 0;
  }

  if (ctx->dev_fd < 0 || ctx->uipi_index < 0) {
    fprintf(stderr,
            "[UINTR SHIM] Error - Invalid TLS state for unregister (fd=%d, "
            "index=%d).\n",
            ctx->dev_fd, ctx->uipi_index);
    // reset state just in case
    ctx->dev_fd = -1;
    ctx->uipi_index = -1;
    ctx->registered = 0;
    ctx->handler_stack = NULL;
    ctx->stack_size = 0;
    return -EINVAL;
  }

  // call the real unregister ioctl
  long ret = ioctl(ctx->dev_fd, UINTR_UNREGISTER_HANDLER,
                   (unsigned long)ctx->uipi_index);
  int saved_errno = errno;

  // close the FD regardless of ioctl result
  if (close(ctx->dev_fd) < 0) {
    if (ret >= 0) {
      perror("[UINTR SHIM] Error closing /dev/uintr fd during unregister");
    } else {
      perror("[UINTR SHIM] Error closing /dev/uintr fd after failed unregister "
             "ioctl");
    }
  }

  // reset TLS state
  ctx->dev_fd = -1;
  ctx->uipi_index = -1;
  ctx->registered = 0;
  ctx->handler_stack = NULL;
  ctx->stack_size = 0;

  if (ret < 0) {
    fprintf(stderr, "[UINTR SHIM] UINTR_UNREGISTER_HANDLER ioctl failed: %s\n",
            strerror(saved_errno));
    return -saved_errno;
  }

  return 0;
}

/*
 * no-op function required by the database interface.
 */
static inline long uintr_create_fd(unsigned int vector, unsigned int flags) {
  _uintr_thread_context_t *ctx = &_uintr_tls_context;

  if (!ctx->registered ||
      ctx->uipi_index < 0) { // check if worker successfully registered
    fprintf(stderr, "[UINTR SHIM] Error - uintr_create_fd called before "
                    "handler was registered or index invalid.\n");
    return -EINVAL;
  }

  // return the ACTUAL UIPI index stored in the worker's TLS
  return (long)ctx->uipi_index;
}

/*
 * returns the UIPI index needed for _senduipi().
 * this index was obtained during the actual registration that should've
 * happened in uintr_register_handler and stored in TLS
 */
static inline long uintr_register_sender(int fd, unsigned int flags) {
  if (fd < 0) {
    fprintf(stderr,
            "[UINTR SHIM] uintr_register_sender called with "
            "potentially invalid index (%d)\n",
            fd);
    return -EINVAL;
  }

  return (long)fd;
}

/*
 * currently a no-op as the driver interface doesn't have an equivalent
 * actual cleanup happens in unregister_handler
 */
static inline long uintr_unregister_sender(int ipi_idx, unsigned int flags) {
  return 0;
}

/*
 * placeholder no-op
 */
static inline long uintr_wait(unsigned int flags) { return 0; }

#ifdef __cplusplus
} // end of extern "C"
#endif

#endif
