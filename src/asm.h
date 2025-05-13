#ifndef INCLUDE_SRC_ASM_H_
#define INCLUDE_SRC_ASM_H_

#ifndef __ASSEMBLY__

/*
 * the following intrinsics map directly to the instructions specified in the
 * Intel SDM Vol. 2B 4-616.
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

#endif // ASM

#endif // INCLUDE_SRC_ASM_H_
