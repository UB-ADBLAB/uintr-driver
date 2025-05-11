#ifndef INCLUDE_SRC_COMMON_H_
#define INCLUDE_SRC_COMMON_H_

#include <linux/types.h>

// TODO: this is dumb
#ifndef __KERNEL__
#include <stddef.h>
#include <stdint.h>
#endif

#define UINTR_HANDLER_FLAG_STACK 0x1;

#define OS_ABI_REDZONE 128

typedef uint64_t uintr_receiver_id_t;
typedef uint64_t uintr_sender_id_t;

struct _uintr_handler_args {
  void *handler;
  void *stack;
  size_t stack_size;
  unsigned int flags;
};

typedef struct {
  uintr_receiver_id_t receiver_id;
  unsigned int vector;
  unsigned int flags;
} _uintr_sender_args;

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
#define UINTR_REGISTER_SENDER _IOW('u', 2, _uintr_sender_args)
#define UINTR_UNREGISTER_SENDER _IOW('u', 3, uintr_sender_id_t)
#define UINTR_DEBUG _IO('u', 4)

#endif // INCLUDE_SRC_COMMON_H_
