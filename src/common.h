#ifndef INCLUDE_SRC_COMMON_H_
#define INCLUDE_SRC_COMMON_H_

#include <linux/types.h>

// TODO: this is dumb
#ifndef __KERNEL__
#include <stddef.h>
#endif

struct _uintr_handler_args {
  void *handler;
  void *stack;
  size_t stack_size;
  unsigned int flags;
};

struct _uintr_vector_args {
  unsigned int vector;
  unsigned int flags;
};

struct _uintr_wait_args {
  unsigned long timeout_us;
  unsigned int flags;
};

struct _uintr_frame {
  unsigned long rip;
  unsigned long rflags;
  unsigned long rsp;
  unsigned long cs;
  unsigned long ss;
  unsigned long vector;
};

#define UINTR_REGISTER_HANDLER _IOW('u', 0, struct _uintr_handler_args)
#define UINTR_UNREGISTER_HANDLER _IO('u', 1)
#define UINTR_CREATE_FD _IOW('u', 2, struct uintr_vector_args)
#define UINTR_WAIT _IOW('u', 3, struct uintr_wait_args)
#define UINTR_DUMP_ENTRY _IOW('u', 4, unsigned int)
#define UINTR_DUMP_MSR _IOW('u', 5, int)

#endif // INCLUDE_SRC_COMMON_H_
