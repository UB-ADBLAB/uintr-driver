#define _GNU_SOURCE
#include "../src/common.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

static int uintr_fd = -1;

/* volatile because value will change when interrupted */
static volatile int interrupt_received = 0;
static volatile sig_atomic_t keep_running = 1;

#define HANDLER_STACK_SIZE (64 * 1024)
static void *handler_stack = NULL;

/* Handler for user interrupts */
void __attribute__((target("uintr"), interrupt))
test_handler(struct __uintr_frame *ui_frame, unsigned long long vector) {
  interrupt_received = 1;
}

static void sigint_handler(int signum) {
  printf("\nCaught signal %d\n", signum);
  keep_running = 0;
}

void *sender_thread(void *arg) {
  int uipi_index = *(int *)arg;

  int cpu = sched_getcpu();
  printf("Sender thread initialized on core: %d \n", cpu);

  sleep(3);

  printf("Sending user interrupt...\n");
  _senduipi(uipi_index);
  printf("User interrupt sent...\n");

  return NULL;
}

int main(void) {
  int ret;
  pthread_t sender_tid;
  int cpu;
  struct sigaction act;

  memset(&act, 0, sizeof(act));
  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, NULL);

  // allocate a dedicated stack for the uintr handler
  handler_stack = aligned_alloc(4096, HANDLER_STACK_SIZE);
  if (!handler_stack) {
    perror("Failed to allocate handler stack");
    return EXIT_FAILURE;
  }
  printf("Allocated handler stack at %p with size %d bytes\n", handler_stack,
         HANDLER_STACK_SIZE);

  // Open the device
  uintr_fd = open("/dev/uintr", O_RDWR);
  if (uintr_fd < 0) {
    perror("Failed to open /dev/uintr");
    return EXIT_FAILURE;
  }

  // Register interrupt handler
  struct _uintr_handler_args handler_args = {.handler = test_handler,
                                             .stack = handler_stack,
                                             .stack_size = HANDLER_STACK_SIZE,
                                             .flags = 0};

  printf("Registering handler 1...\n");
  int idx_1 = ioctl(uintr_fd, UINTR_REGISTER_HANDLER, &handler_args);
  if (idx_1 < 0) {
    perror("Failed to register handler 1");
    goto cleanup;
  }
  printf("Got assigned index %d from registering handler 1.\n", idx_1);

  sleep(1);

  printf("Registering handler 2...\n");
  int uipi_index = ioctl(uintr_fd, UINTR_REGISTER_HANDLER, &handler_args);
  if (uipi_index < 0) {
    perror("Failed to register handler 1");
    goto cleanup;
  }
  printf("Got assigned index %d from registering handler 2.\n", uipi_index);

  ioctl(uintr_fd, UINTR_DUMP_ENTRY, idx_1);
  ioctl(uintr_fd, UINTR_DUMP_ENTRY, uipi_index);

  // Enable user interrupts
  printf("Current UIF before stui: %u\n", _testui());
  _stui();
  if (!_testui()) {
    printf("[ERROR] UIF not set after _stui()!\n");
    goto cleanup;
  }
  printf("UIF set successfully. UIF after stui: %u\n", _testui());

  // Start a sender thread with idx 2
  ret = pthread_create(&sender_tid, NULL, sender_thread, &uipi_index);
  if (ret != 0) {
    perror("Failed to create sender thread");
    goto cleanup;
  }

  cpu = sched_getcpu();
  printf("Main thread running on core: %d\n", cpu);
  printf("Waiting for interrupt...\n");

  ioctl(uintr_fd, UINTR_DUMP_MSR, cpu);

  while (!interrupt_received && keep_running) {
  }

  if (!keep_running) {
    printf("Interrupted by user\n");
    return EXIT_SUCCESS;
  }

  printf("User interrupt received!\n");
  pthread_join(sender_tid, NULL);
  printf("Test completed successfully!\n");
  ret = EXIT_SUCCESS;

cleanup:
  _clui();

  if (uintr_fd >= 0) {
    ioctl(uintr_fd, UINTR_UNREGISTER_HANDLER, uipi_index);
    close(uintr_fd);
  }
  return ret;
}
