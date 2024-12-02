#ifndef _UAPI_ASM_X86_UINTR_H
#define _UAPI_ASM_X86_UINTR_H

struct uintr_handler_args {
    void *handler;
    void *stack;
    size_t stack_size;
    unsigned int flags;
};

struct uintr_vector_args {
    unsigned int vector;
    unsigned int flags;
};

struct uintr_wait_args {
    unsigned long timeout_us;
    unsigned int flags;
};

struct __uintr_frame {
  unsigned long rip;
  unsigned long rflags;
  unsigned long rsp;
  unsigned long cs;
  unsigned long ss;
  unsigned long vector;
};

#define UINTR_REGISTER_HANDLER _IOW('u', 0, struct uintr_handler_args)
#define UINTR_UNREGISTER_HANDLER _IO('u', 1)
#define UINTR_CREATE_FD _IOW('u', 2, struct uintr_vector_args) 
#define UINTR_WAIT _IOW('u', 3, struct uintr_wait_args)

#ifndef __ASSEMBLY__

/*
 * the following intrinsics map directly to the instructions specified in the Intel SDM Vol. 2B 4-616.
 */

/* Set User Interrupt Flag - enables user interrupts */
static __always_inline void _stui(void) {
  __asm__ __volatile__("stui" : : : "memory");
}

/* Clear User Interrupt Flag - disables user interrupts */
static __always_inline void _clui(void) {
  __asm__ __volatile__("clui" : : : "memory");
}

/* Determine User Interrupt Flag - returns current UIF value */
static __always_inline unsigned char _testui(void) {
  unsigned char cf;
  __asm__ __volatile__("testui" : "=@ccb"(cf) : : "cc");
  return cf;
}

/* Send User Interrupt - sends a user interrupt to the index set in the register */
static __always_inline void _senduipi(unsigned long uipi_index) {
  __asm__ __volatile__("senduipi %0" : : "r"(uipi_index) : "memory");
}

/* Return from user interrupt handler */
static __always_inline void _uiret(void) {
  __asm__ __volatile__("uiret" : : : "memory");
}

#endif
#endif
