#ifndef _UAPI_ASM_X86_UINTR_H
#define _UAPI_ASM_X86_UINTR_H

#include <fcntl.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

typedef uint64_t uintr_receiver_id_t;
typedef uint64_t uintr_sender_id_t;

typedef struct {
  void *handler;
  void *stack;
  size_t stack_size;
  unsigned int flags;
} _uintr_handler_args;

typedef struct {
  uintr_receiver_id_t receiver_id;
  unsigned int vector;
  unsigned int flags;
} _uintr_sender_args;

struct _uintr_frame {
  unsigned long long rip;
  unsigned long long rflags;
  unsigned long long rsp;
};

#define UINTR_REGISTER_HANDLER _IOW('u', 0, _uintr_handler_args)
#define UINTR_UNREGISTER_HANDLER _IO('u', 1)
#define UINTR_REGISTER_SENDER _IOW('u', 2, _uintr_sender_args)
#define UINTR_UNREGISTER_SENDER _IOW('u', 3, uintr_sender_id_t)
#define UINTR_DEBUG _IO('u', 4)

/**
 * @brief Registers a user interrupt handler for the current process.
 *
 * @param handler Pointer to the handler function that will be called when an
 * interrupt is received.
 * @param stack Pointer to a user-allocated stack for the interrupt handler. If
 * NULL, the handler will use the current stack with a red zone adjustment
 * offset.
 * @param stack_size Size of the allocated stack in bytes.
 * @param flags Configuration flags for registering handlers.
 *
 * @return On success, returns a positive non-zero receiver ID that identifies
 * this handler.
 *
 * @note Registering multiple handlers per process is undefined behavior
 * @note The caller must set UIF (user interrupt flag) using the _stui()
 * intrinsic to enable interrupt delivery
 **/
uintr_receiver_id_t uintr_register_handler(void *handler, void *stack,
                                           size_t stack_size,
                                           unsigned int flags);

/**
 * @brief Unregisters a user interrupt handler.
 *
 * @param receiver_id The receiver ID of the handler to unregister.
 *
 * @returns Returns 0 on success
 **/
int uintr_unregister_handler(uintr_receiver_id_t receiver_id);

/**
 * @brief Registers a sender on the current process for a specified receiver.
 *Multiple senders may be registered per process.
 *
 * @param receiver_id The receiver ID of the handler to send interrupts to.
 *
 * @param vector The vector that is pushed onto the stack when in the interrupt
 * handler triggered by the interrupt.
 *
 * @param flags Configuration flags for the sender.
 *
 * @returns The index of the UITT that belongs to the corresponding entry.
 **/
int uintr_register_sender(uintr_receiver_id_t receiver_id, unsigned int vector,
                          unsigned int flags);

/**
 * @brief Unregisters a sender for the current process based off its index in
 * the process's UITT.
 *
 * @param idx The index previously returned by uintr_register_sender that
 * identifies which sender to remove.
 *
 * @note All senders should be unregistered before the process exits to avoid
 * resource leaks
 **/
int uintr_unregister_sender(int idx);

int uintr_debug(void);

/* --- Intrinsics ---
 *
 * the following intrinsics map directly to the instructions specified in the
 * Intel SDM Vol. 2B 4-616.
 */

#ifndef __ASSEMBLY__

/* Set User Interrupt Flag - enables user interrupts */
static __always_inline void __stui(void) {
  __asm__ __volatile__("stui" : : : "memory");
}

/* Clear User Interrupt Flag - disables user interrupts */
static __always_inline void __clui(void) {
  __asm__ __volatile__("clui" : : : "memory");
}

/* Determine User Interrupt Flag - returns current UIF value */
static __always_inline unsigned char __testui(void) {
  unsigned char cf;
  __asm__ __volatile__("testui" : "=@ccb"(cf) : : "cc");
  return cf;
}

/* Send User Interrupt - sends a user interrupt to the index set in the register
 */
static __always_inline void __senduipi(unsigned long uipi_index) {
  __asm__ __volatile__("senduipi %0" : : "r"(uipi_index) : "memory");
}

/* Return from user interrupt handler */
static __always_inline void __uiret(void) {
  __asm__ __volatile__("uiret" : : : "memory");
}

#endif

#endif
