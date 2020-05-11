#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "AES.h"

byte* charPtr2wordPtr(char* CipherKey){
    byte* key = (byte*)calloc(Nk*4,sizeof(byte));
    // char* temp = (char*)calloc(Nb*8+16,sizeof(char));
    // for(int i = 0, j = 0;*CipherKey;*CipherKey++){
    //     temp[j++] = *CipherKey;
    //     if( ++i % 2 == 0){
    //         temp[j++] = ' ';
    //     }
    // }
    // temp[47] = '\0';
    // printf("%s\n",temp);
    // char* pEnd = temp;
    // for(int i = 0; *temp; i++) {
    //     key[i] = (word)strtol(temp,&temp,16);
    // }
    
    // for(int i = 0; i < 16;) {
    //     printf("%.2x ",key[i++]);
    //     if( ! i % 4 ){
    //         printf("\n");
    //     }
    // }

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
    AES.init(CipherKey,w);
    // for(int i = 0; i < Nb*(Nr+1);){
    //     printf("%.8X ",w[i/4*4+i%4]);
    //     if((++i % 4)==0) printf("\n"); 
    // }
    // AES.cipher();
    return 0;
}