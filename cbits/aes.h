#ifndef _IAESNI_H__
#define _IAESNI_H__

#include <stdlib.h>

#define AES_INSTRUCTIONS_CPUID_BIT (1<<25)

// Test if the processor actually supports AESNI.
int has_aes_ni(void);

#endif
