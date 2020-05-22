#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "AES.h"

void printf_block(byte b[4*Nb]){
    for(int i = 0; i < 4 * Nb;){
        printf("%.2X ",b[i/4*4+i%4]);
        if((++i % 4)==0) printf("\n"); 
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char* CipherKey = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
    word w[Nb*(Nr+1)] = {0};
    AES_Initialize(CipherKey,w);

    byte in[4*Nb] = { 
        0x32, 0x43, 0xF6, 0xA8, 
        0x88, 0x5A, 0x30, 0x8D,
        0x31, 0x31, 0x98, 0xA2,
        0xE0, 0x37, 0x07, 0x34
    };

    printf("Plaintext:\n");
    printf_block(in);

    byte out[4*Nb] = { 0 };
    AES_Cipher(in, out, w);
    
    printf("ciphertext:\n");
    printf_block(out);

    byte Plaintext[4*Nb] = { 0 };
    AES_InvCipher(out, Plaintext, w);
    
    printf("Plaintext:\n");
    printf_block(Plaintext);
    return 0;
}