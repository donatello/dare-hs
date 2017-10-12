#include "aes.h"

#include <stdio.h>
#include <string.h>

#if defined __linux__ || defined __APPLE__
static void __cpuid(unsigned int where[4], unsigned int leaf) {
        asm volatile("cpuid":"=a"(*where),"=b"(*(where+1)), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
        return;
}
#else // Windows
#include <intrin.h>
#endif

/*
 * has_aes_ni
 *   return 1 if support AES-NI and 0 if don't support AES-NI
 */

int has_aes_ni(void)
{
        unsigned int cpuid_results[4];

        __cpuid(cpuid_results, 0);
         if (cpuid_results[0] < 1)
                return 0;
/*
 *      MSB         LSB
 * EBX = 'u' 'n' 'e' 'G'
 * EDX = 'I' 'e' 'n' 'i'
 * ECX = 'l' 'e' 't' 'n'
 */

        int intel = 1;
        int amd   = 1;

        // AuthenticAMD verify
        if (memcmp((unsigned char *)&cpuid_results[1], "Genu", 4) != 0 ||
            memcmp((unsigned char *)&cpuid_results[3], "ineI", 4) != 0 ||
            memcmp((unsigned char *)&cpuid_results[2], "ntel", 4) != 0)
                intel = 0;

        if (memcmp((unsigned char *)&cpuid_results[1], "Auth", 4) != 0 ||
            memcmp((unsigned char *)&cpuid_results[3], "enti", 4) != 0 ||
            memcmp((unsigned char *)&cpuid_results[2], "cAMD", 4) != 0)
                amd = 0;

        if (intel || amd)
        {
                __cpuid(cpuid_results, 1);
                if (cpuid_results[2] & AES_INSTRUCTIONS_CPUID_BIT)
                        return 1;
        }
        return 0;
}
