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

/* volatile because value will change when interrupted */
static volatile int interrupt_received = 0;

/* Handler for user interrupts */
void __attribute__((interrupt)) test_handler(struct __uintr_frame *ui_frame,
                                             unsigned long long vector) {
  interrupt_received = 1;
}

/* Helper function to set thread affinity */
static int set_thread_affinity(pthread_t thread, int core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);

  int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (ret != 0) {
    printf("Failed to set thread affinity to core %d: %s\n", core,
           strerror(ret));
    return -1;
  }
  return 0;
}

void *sender_thread(void *arg) {
  int uipi_index = *(int *)arg;

  // Set sender thread affinity to core 2
  if (set_thread_affinity(pthread_self(), 2) != 0) {
    return NULL;
  }

  int cpu = sched_getcpu();
  printf("Sender thread initialized on core: %d\n", cpu);

  sleep(1);
  printf("Sending user interrupt...\n");
  _senduipi(uipi_index);
  printf("User interrupt sent...\n");

  return NULL;
}

int main(void) {
  int ret;
  pthread_t sender_tid;
  int cpu;

  // Set main thread affinity to core 0
  if (set_thread_affinity(pthread_self(), 0) != 0) {
    return EXIT_FAILURE;
  }

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

  cpu = sched_getcpu();
  printf("Main thread running on core: %d\n", cpu);
  printf("Waiting for interrupt...\n");

  while (!interrupt_received) {
  }

  printf("User interrupt received!\n");
  pthread_join(sender_tid, NULL);
  printf("Test completed successfully!\n");
  ret = EXIT_SUCCESS;

cleanup:
  _clui();

  if (uintr_fd >= 0) {
    ioctl(uintr_fd, UINTR_UNREGISTER_HANDLER);
    close(uintr_fd);
  }
  return ret;
}
