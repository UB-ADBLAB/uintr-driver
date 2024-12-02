#include "../include/uapi/linux/uintr.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int uintr_fd = -1;
static int vector_fd = -1;

/* volatile because value will change when interrupted */
static volatile int interrupt_received = 0;

/* Handler for user interrupts */
void __attribute__((interrupt))
test_handler(struct __uintr_frame *ui_frame, unsigned long long vector) {
  interrupt_received = 1;
  printf("Received interrupt on vector %llu\n", vector);
}

void *sender_thread(void *arg) {
  int uipi_index = *(int *)arg;

  /* may need to sleep for a second here until receiver is ready... */
  printf("Sending user interrupt...\n");
  _senduipi(uipi_index);

  return NULL;
}

int main(void) {
  int ret;
  pthread_t sender_tid;

  // Open the device
  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    perror("Failed to open /dev/uintr");
    return EXIT_FAILURE;
  }

  // Register interrupt handler
  struct uintr_handler_args handler_args = {
      .handler = test_handler, .stack = NULL, .stack_size = 0, .flags = 0};

  ret = ioctl(uintr_fd, UINTR_REGISTER_HANDLER, &handler_args);
  if (ret < 0) {
    perror("Failed to register handler");
    goto cleanup;
  }

  // Create a vector
  struct uintr_vector_args vec_args = {.vector = 0, .flags = 0};

  vector_fd = ioctl(uintr_fd, UINTR_CREATE_FD, &vec_args);
  if (vector_fd < 0) {
    perror("Failed to create vector");
    goto cleanup;
  }

  // Enable user interrupts
  _stui();

  /*
   * Create sender thread, similar to Intel's test we'll just assume the index
   * of the UITE
   */
  int uipi_index = 0;
  ret = pthread_create(&sender_tid, NULL, sender_thread, &uipi_index);
  if (ret != 0) {
    perror("Failed to create sender thread");
    goto cleanup;
  }

  // Wait for interrupt
  printf("Waiting for interrupt...\n");
  while (!interrupt_received) {
    asm volatile("pause" ::: "memory");
  }

  pthread_join(sender_tid, NULL);
  printf("Test completed successfully!\n");
  ret = EXIT_SUCCESS;

cleanup:
  _clui();

  if (vector_fd >= 0) {
    close(vector_fd);
  }

  if (uintr_fd >= 0) {
    ioctl(uintr_fd, UINTR_UNREGISTER_HANDLER);
    close(uintr_fd);
  }

  return ret;
}
