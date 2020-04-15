#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#ifdef  __cplusplus
extern  "C" {
#endif 

#ifndef __NB
#define __NB 4
#endif

#ifdef AES_FLAVIRO
#if AES_FLAVIRO == 128
#define __NR 10
#define __NK 4
#endif
#if AES_FLAVIRO == 192
#define __NR 12
#define __NK 6
#endif 
#if AES_FLAVIRO == 256
#define __NR 14
#define __NK 8 
#endif
#define Nb 4
#else 
#define AES_FLAVIRO 128
#define __NR 10
#define __NK 4
#endif


typedef uint32_t word; 
typedef uint8_t byte;
void Cipher(byte in[4*__NB], byte out[4*__NB], word w[__NB*(__NR+1)]);

#ifdef  __cplusplus
}
#endif 
#endif