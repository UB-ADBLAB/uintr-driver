#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <x86intrin.h>
#include "../src/common.h"

static int uintr_fd = -1;
static volatile int interrupt_received = 0;
static volatile sig_atomic_t keep_running = 1;
#define HANDLER_STACK_SIZE (64 * 1024)
static void *handler_stack = NULL;
static int uipi_index = -1;

static void cleanup(void) {
  printf("\nCleaning up...\n");
  /* Disable interrupts before cleanup */
  _clui();
  if (uintr_fd >= 0) {
    printf("Unregistering handler...\n");
    ioctl(uintr_fd, UINTR_UNREGISTER_HANDLER, uipi_index);
    close(uintr_fd);
    uintr_fd = -1;
  }
  if (handler_stack) {
    free(handler_stack);
    handler_stack = NULL;
  }
}

/* Handler for user interrupts */
void __attribute__((target("uintr"), interrupt))
test_handler(struct __uintr_frame *ui_frame, unsigned long long vector) {
  interrupt_received = 1;
}

static void sigint_handler(int signum) {
  printf("\nCaught signal %d\n", signum);
  keep_running = 0;
}

/* Helper function to set thread affinity to a specific core */
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
  int cpu;
  int target_core = 1;

  // Set initial core affinity
  set_thread_affinity(pthread_self(), target_core);

  cpu = sched_getcpu();
  printf("Sender thread initialized on core: %d\n", cpu);

  // Wait briefly to ensure handler is ready
  sleep(2);

  printf("Sending user interrupt...\n");
  _senduipi(uipi_index);
  printf("User interrupt sent...\n");

  return NULL;
}

int main(void) {
  int ret;
  pthread_t sender_tid;
  int num_cores = get_nprocs();
  struct sigaction act;

  memset(&act, 0, sizeof(act));
  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, NULL);

  atexit(cleanup);

  // Start on core 0
  set_thread_affinity(pthread_self(), 0);
  printf("Main thread starting on core: %d\n", sched_getcpu());

  // Allocate handler stack
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

  printf("Registering handler...\n");
  uipi_index = ioctl(uintr_fd, UINTR_REGISTER_HANDLER, &handler_args);
  if (uipi_index < 0) {
    perror("Failed to register handler");
    goto cleanup;
  }
  printf("Got assigned index %d from registering handler.\n", uipi_index);

  // Enable user interrupts
  printf("Current UIF before stui: %u\n", _testui());
  _stui();
  if (!_testui()) {
    printf("[ERROR] UIF not set after _stui()!\n");
    cleanup();
    return EXIT_FAILURE;
  }
  printf("UIF set successfully. UIF after stui: %u\n", _testui());

  // Create the sender thread on a different core
  ret = pthread_create(&sender_tid, NULL, sender_thread, NULL);
  if (ret != 0) {
    perror("Failed to create sender thread");
    goto cleanup;
  }

  // force migration to another core
  int next_core = 2; // Move to core 2 if available
  printf("Migrating main thread to core %d before interrupt...\n", next_core);
  set_thread_affinity(pthread_self(), next_core);
  printf("Main thread now on core: %d\n", sched_getcpu());

  // Small delay to ensure migration
  usleep(500000); // 500ms

  printf("Waiting for interrupt...\n");
  while (!interrupt_received && keep_running) {
  }

  if (!keep_running) {
    printf("Interrupted by user\n");
    pthread_join(sender_tid, NULL);
    ret = EXIT_SUCCESS;
    goto cleanup;
  }

  printf("User interrupt received on core %d!\n", sched_getcpu());
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
