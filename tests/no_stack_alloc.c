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
#include <sys/mman.h>
#include <uintrdriv.h>
#include <unistd.h>
#include <x86intrin.h>

/* volatile because value will change when interrupted */
static volatile int interrupt_received = 0;
static volatile sig_atomic_t keep_running = 1;

static void cleanup(void) {
  printf("\nCleaning up...\n");

  /* Disable interrupts before cleanup */
  _clui();
}

/* Handler for user interrupts */
void __attribute__((target("uintr"), interrupt))
test_handler(struct __uintr_frame *ui_frame, unsigned long long vector) {
  interrupt_received++;
}

static void sigint_handler(int signum) {
  printf("\nCaught signal %d\n", signum);
  keep_running = 0;
}

void *sender_thread(void *arg) {
  uintr_receiver_id_t receiver_id = *(uintr_receiver_id_t *)arg;
  int idx = -1;

  int cpu = sched_getcpu();
  printf("Sender thread initialized on core: %d, pid: %d\n", cpu, getpid());

  sleep(3);

  idx = uintr_register_sender(receiver_id, 0, 0);
  printf("Got idx: %d\n", idx);

  sleep(3);

  printf("Sending user interrupt...\n");
  _senduipi(idx);
  printf("User interrupt sent...\n");

  uintr_unregister_sender(idx);

  return NULL;
}

int main(void) {
  int ret;
  pthread_t sender1;
  int cpu;
  struct sigaction act;

  memset(&act, 0, sizeof(act));
  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, NULL);

  uintr_receiver_id_t receiver_id = 0;
  receiver_id = uintr_register_handler(test_handler, NULL, 0, 0);

  // Enable user interrupts
  printf("Current UIF before stui: %u\n", _testui());
  _stui();
  if (!_testui()) {
    printf("[ERROR] UIF not set after _stui()!\n");
    cleanup();
    return EXIT_FAILURE;
  }
  printf("UIF set successfully. UIF after stui: %u\n", _testui());

  ret = pthread_create(&sender1, NULL, sender_thread, &receiver_id);
  if (ret != 0) {
    perror("Failed to create sender thread 1\n");
    cleanup();
  }

  sleep(2);
  cpu = sched_getcpu();
  printf("Main thread running on core: %d\n", cpu);
  sleep(3);
  cpu = sched_getcpu();
  printf("Main thread migrated to core: %d\n", cpu);
  printf("Waiting for interrupt...\n");

  while (!interrupt_received && keep_running) {
  }

  if (!keep_running) {
    printf("Interrupted by user\n");
    return EXIT_SUCCESS;
  }

  printf("User interrupt received!\n");
  pthread_join(sender1, NULL);
  printf("Test completed successfully!\n");
  ret = EXIT_SUCCESS;

  // clean up
  _clui();

  uintr_unregister_handler(receiver_id);

  return ret;
}
