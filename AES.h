#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#ifdef  __cplusplus
extern  "C" {
#endif 

#ifndef Nb
#define Nb 4
#endif

#ifndef AES_FLAVIRO
#define AES_FLAVIRO 128
#define Nr 10
#define Nk 4
#else 
#if AES_FLAVIRO == 192
#define Nr 12
#define Nk 6
#endif 
#if AES_FLAVIRO == 256
#define Nr 14
#define Nk 8 
#endif

#endif

typedef uint32_t word; 
typedef uint8_t byte;
extern void AES_Initialize(char* cipherkey, word w[Nb*(Nr+1)]);
extern void AES_Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]);
extern void AES_InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]);

#ifdef  __cplusplus
}
#endif 
#endif