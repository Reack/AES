#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "AES.h"

byte* charPtr2wordPtr(char* CipherKey){
    byte* key = (byte*)calloc(Nk*4,sizeof(byte));
    char* temp =CipherKey;
    for(int i = 0; *temp; i++) {
        key[i] = (word)strtol(temp,&temp,16);
    }
    return key;
}

int main(int argc, char *argv[]) {
    char* CipherKey = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
    charPtr2wordPtr(CipherKey);
    word w[Nb*(Nr+1)] = {0};
    aes_initialize(CipherKey,w);

    byte in[4*Nb] = { 
        0x32, 0x43, 0xF6, 0xA8, 
        0x88, 0x5A, 0x30, 0x8D,
        0x31, 0x31, 0x98, 0xA2,
        0xE0, 0x37, 0x07, 0x34
    };

    byte out[4*Nb] = { 0 };
    aes_cipher(in, out, w);
    return 0;
}