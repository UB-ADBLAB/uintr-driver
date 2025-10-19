#define _GNU_SOURCE
#include "../include/uintrdriv.h"
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

/* volatile because value will change when interrupted */
static volatile int interrupt_received = 0;
static volatile sig_atomic_t keep_running = 1;

static void cleanup(void) {
  printf("\nCleaning up...\n");

  /* Disable interrupts before cleanup */
  __clui();
}

/* Handler for user interrupts */
void __attribute__((target("uintr"), interrupt))
test_handler(struct _uintr_frame *ui_frame, unsigned long long vector) {
  interrupt_received = 1;
}

static void sigint_handler(int signum) {
  printf("\nCaught signal %d\n", signum);
  keep_running = 0;
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
  uintr_receiver_id_t receiver_id = *(uintr_receiver_id_t *)arg;
  int idx = -1;

  // Set sender thread affinity to core 2
  if (set_thread_affinity(pthread_self(), 2) != 0) {
    return NULL;
  }

  int cpu = sched_getcpu();
  printf("Sender thread initialized on core: %d \n", cpu);

  sleep(3);

  idx = uintr_register_sender(receiver_id, 0, 0);

  sleep(3);

  printf("Sending user interrupt...\n");
  __senduipi(idx);
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

  // Set main thread affinity to core 0
  if (set_thread_affinity(pthread_self(), 0) != 0) {
    return EXIT_FAILURE;
  }

  // allocate a dedicated stack for the uintr handler
  uintr_receiver_id_t receiver_id = 0;
  receiver_id = uintr_register_handler(test_handler, NULL, 0, 0);

  // Enable user interrupts
  printf("Current UIF before stui: %u\n", __testui());
  __stui();
  if (!__testui()) {
    printf("[ERROR] UIF not set after __stui()!\n");
    cleanup();
    return EXIT_FAILURE;
  }
  printf("UIF set successfully. UIF after stui: %u\n", __testui());

  ret = pthread_create(&sender_tid, NULL, sender_thread, &receiver_id);
  if (ret != 0) {
    perror("Failed to create sender thread");
    goto cleanup;
  }

  cpu = sched_getcpu();
  printf("Main thread running on core: %d\n", cpu);
  printf("Waiting for interrupt...\n");

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
  __clui();

  return ret;
}
