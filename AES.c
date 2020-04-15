#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "AES.h"

#define ROTL8(x,shift) ((byte) ((x) << (shift)) | ((x) >> (8 - (shift))))


// void initialize_aes(){

//     initialize_aes_sbox(sbox[256])
// }
byte __sbox[256];

void __initialize_aes_sbox(byte sbox[256]) {
	byte p = 1, q = 1;
	
	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		byte xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
}

void __covert_io_state(byte in[4*__NB],byte out[4*__NB]){
    for ( uint8_t i = 0; i < 4*__NB; i++) {
        out[i] = in[( ( i * 4 ) % 16 ) + ( i / 4 )];
    }
}

void Cipher(byte in[4*__NB], byte out[4*__NB], word w[__NB*(__NR+1)]) {
    byte *state = (byte*)calloc(4*__NB,sizeof(byte));
    __covert_io_state(in,state);
    // AddRoundKey(state, w[0, __NB-1]); // See Sec. 5.1.4
    // for ( uint8_t round = 1; round <= __NR-1; round++ ) {
    //     SubBytes(state); // See Sec. 5.1.1
    //     ShiftRows(state); // See Sec. 5.1.2
    //     MixColumns(state); // See Sec. 5.1.3
    //     AddRoundKey(state, w[round*__NB, (round+1)*__NB-1]);
    // }
    // SubBytes(state);
    // ShiftRows(state);
    // AddRoundKey(state, w[__NR*__NB, (__NR+1)*__NB-1]);
    __covert_io_state(state,out);
}

uint8_t SubBytes(byte state[4*__NB]){
    for ( uint8_t i = 0; i < 4*__NB; i++ ) {
        state[i] = __sbox[state[i]];
    }
}

uint8_t ShiftRows(byte state[4*__NB]){
    byte temp1;
    byte temp2;
    for ( uint8_t i = 0; i < 4; i++ ) {
        uint8_t j = 4 - i;
        for ( uint8_t round = 1; round < 4; round++) {
            uint8_t sw = (!(i%2))&(!(round%2));
            temp2 = temp1;
            temp1 = state[i*4+(j+sw*3)%4];
            state[i*4+j] = temp2;
            j = (j+4-i)%4 + sw;
        }
    }
}

uint8_t MixColumns(byte state[4*__NB]) {
    
}

uint8_t AddRoundKey(byte state[4*__NB]) {
    
}