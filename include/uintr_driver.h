#ifndef _UAPI_ASM_X86_UINTR_H
#define _UAPI_ASM_X86_UINTR_H

#include "../src/common.h"

#include <fcntl.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

uintr_receiver_id_t uintr_register_handler(void *handler, void *stack,
                                           size_t stack_size,
                                           unsigned int flags) {
  int uintr_fd;
  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    return EXIT_FAILURE;
  }

  _uintr_handler_args handler_args = {
      .handler = handler,
      .stack = stack,
      .stack_size = stack_size,
      .flags = flags,
  };

  uintr_receiver_id_t id = 0;
  id = ioctl(uintr_fd, UINTR_REGISTER_HANDLER, &handler_args);

  close(uintr_fd);
  return id;
}

int uintr_unregister_handler(uintr_receiver_id_t receiver_id) {
  int uintr_fd;
  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    return EXIT_FAILURE;
  }

  ioctl(uintr_fd, UINTR_UNREGISTER_HANDLER, receiver_id);

  close(uintr_fd);
  return 0;
}

int uintr_register_sender(uintr_receiver_id_t receiver_id, unsigned int vector,
                          unsigned int flags) {
  int id = 0;
  int uintr_fd;

  _uintr_sender_args sender_args = {
      .receiver_id = receiver_id,
      .vector = vector,
      .flags = flags,
  };

  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    return EXIT_FAILURE;
  }

  id = ioctl(uintr_fd, UINTR_REGISTER_SENDER, &sender_args);

  close(uintr_fd);
  return id;
}

int uintr_unregister_sender(int idx) {
  int uintr_fd;

  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    return EXIT_FAILURE;
  }

  ioctl(uintr_fd, UINTR_UNREGISTER_SENDER, idx);

  close(uintr_fd);
  return 0;
}

int uintr_debug(void) {
  int uintr_fd;

  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    return EXIT_FAILURE;
  }

  ioctl(uintr_fd, UINTR_DEBUG);

  close(uintr_fd);
  return 0;
}

#endif
