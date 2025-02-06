#define _GNU_SOURCE

#include "../include/uapi/linux/uintr.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
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
void __attribute__((interrupt)) test_handler(struct __uintr_frame *ui_frame,
                                             unsigned long long vector) {
  interrupt_received = 1;
}

void *sender_thread(void *arg) {
  int uipi_index = *(int *)arg;
  int cpu;

  cpu = sched_getcpu();

  printf("Sender thread initialize on thread: %d\n", cpu);

  sleep(1);

  printf("Sending user interrupt...\n");
  _senduipi(uipi_index);
  printf("User interrupt sent...\n");

  return NULL;
}

int main(void) {
  int ret;
  pthread_t sender_tid;
  cpu_set_t cpuset;
  int cpu;

  // We'll try to pin our main process to CPU 0 using CPU_SET
  cpu = 0;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);

  // Open the device
  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    perror("Failed to open /dev/uintr");
    return EXIT_FAILURE;
  }

  // Register interrupt handler
  struct uintr_handler_args handler_args = {
      .handler = test_handler, .stack = NULL, .stack_size = 0, .flags = 0};

  printf("Registering handler...\n");
  int uipi_index = ioctl(uintr_fd, UINTR_REGISTER_HANDLER, &handler_args);
  if (uipi_index < 0) {
    perror("Failed to register handler");
    goto cleanup;
  }
  printf("Got assigned index %d from registering handler.\n", uipi_index);

  // Enable user interrupts
  _stui();

  ret = pthread_create(&sender_tid, NULL, sender_thread, &uipi_index);
  if (ret != 0) {
    perror("Failed to create sender thread");
    goto cleanup;
  }

  printf("Waiting for interrupt...\n");
  while (!interrupt_received) {
    /*cpu = sched_getcpu();*/
    /*printf("\rsimplified_pinned is currently on thread: %d", cpu);*/
    /*fflush(stdout);*/
  }
  printf("User interrupt received!\n");

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
