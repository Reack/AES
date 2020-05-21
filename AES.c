#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "AES.h"

#define ROTL8(x,shift) ((byte) ((x) << (shift)) | ((x) >> (8 - (shift))))

byte sbox[256];
word rcon[Nr+1];

void aes_initialize_sbox(byte sbox[256]) {
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
void aes_covert_io_state(byte in[4*Nb],byte out[4*Nb]){
    for ( uint8_t i = 0; i < 4*Nb; i++) {
        out[i] = in[( ( i * 4 ) % 16 ) + ( i / 4 )];
    }
}

byte aes_FFM(byte x, byte y) { // p(x) = x^8 + x^4 + X^3 + X + 1
    byte result = 0;
    for ( uint8_t i = 0x80; i > 0x1; i>>=1 ){
        result = ( result ^ ( ( (!!( ( y & i ) ^ i )) + 0xFF ) & x ) );
        result = ( ( !( result & 0x80 ) + 0xFF) & 0x1B ) ^ ( result << 1 ); 
    }
    return ( result ^ ( ( ( ( y & 0x01 ) ^ 0x01) + 0xFF ) & x ) );
}

void aes_initialize_rcon(word rcon[Nr+1]) {
    rcon[0] = 1<<24;
    for ( uint8_t i = 1; i <  Nr+1; i++) {
        uint8_t ge = rcon[i-1] >> 24;
        ge = ( ge << 1 ) ^ ( ( !( ge & 0x80 ) + 0xFF ) & 0x1B );
        rcon[i] = ge << 24;
    }
}

void ckey2bkey(char* cipherkey, byte key[4*Nk]){
    char* temp = cipherkey;
    for(int i = 0; *temp; i++) {
        key[i] = (word)strtol(temp,&temp,16);
    }
}

void SubBytes(byte state[4*Nb]){
    for ( uint8_t i = 0; i < 4*Nb; i++ ) {
        state[i] = sbox[state[i]];
    }
}

word SubWord(word w) {
    for ( uint8_t i = 0; i < 4; i++) {
        word ofset = i << 3;
        word mask = 0xff<<ofset;
        w = ( w & ( ~mask ) ) | ( sbox[ (byte)( ( w & ( mask ) ) >> ofset ) ] << ofset);
    }
    return w;
}

word RotWord(word w) {
    return ( w << 8 ) | ( ( w & 0xFF000000 ) >> 24 );
}

void ShiftRows(byte state[4*Nb]){
    for ( uint8_t i = 1; i < 4; i++ ) {
        uint8_t j = 4 - i;
        byte temp1 = state[i*4];
        byte temp2;
        for ( uint8_t round = 1; round <= 4; round++) {
            uint8_t sw = (!(i%2))&(!(round%2));
            temp2 = temp1;
            temp1 = state[i*4+(j+sw*3)%4];
            state[i*4+j] = temp2;
            j = ( j + 4 - i + sw * 3 ) % 4;
        }
    }
}

void MixColumns(byte state[4*Nb]) {
    for ( uint8_t c = 0; c < 4; c++ ) {
        byte temp0 = aes_FFM( 0x02, state[ c ] ) ^ aes_FFM( 0x03, state[ 4 + c ] ) ^ state[ 8 + c ] ^ state[ 12 + c ];
        byte temp1 = state[ c ] ^ aes_FFM( 0x02, state[ 4 + c ]) ^ aes_FFM( 0x03, state[ 8 + c ] ) ^ state[ 12 + c ];
        byte temp2 = state[ c ] ^ state[ 4 + c ] ^ aes_FFM( 0x02, state[ 8 + c ] ) ^ aes_FFM( 0x03, state[ 12 + c ] );
        byte temp3 = aes_FFM( 0x03, state[ c ] )^state[ 4 + c ]^state[ 8 + c ]^ aes_FFM( 0x02, state[ 12 + c ] );
        state[c] = temp0;
        state[4+c] = temp1;
        state[8+c] = temp2;
        state[12+c] =  temp3;
    }
}

void AddRoundKey(byte state[4*Nb], word w[4]) {
    for ( uint8_t round = 0; round < 4; round++ ) {
        int32_t temp =  state[ 12 + round ] | ( state[ 8 + round ] << 8 ) | ( (state[ 4 + round ]) << 16 ) | ( (state[ round ]) << 24 );
        temp = temp ^ w[round];
        state[ 12 +  round ] = temp & 0xFF;
        state[ 8 + round ] = ( temp >> 8 ) & 0xFF;
        state[ 4 + round ] = ( temp >> 16 ) & 0xFF;
        state[round ] = ( temp >> 24 ) & 0xFF;
    }
}

void KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], uint8_t NK){
    uint8_t i = 0;
    while ( i < NK) {
        w[i] = ( key[ 4 * i ] << 24 ) | ( key[ 4 * i + 1 ] << 16 ) | ( key[ 4 * i + 2 ] << 8 ) | key[ 4 * i + 3 ];
        i++;
    }

    i = NK;

    while ( i < Nb * ( Nr + 1 )){
        word temp = w[ i - 1 ];
        if ( i % NK == 0){
            temp = SubWord( RotWord( temp ) ) ^ rcon[ (i / NK) - 1];
        } else if (NK > 6 && (i % NK == 4)){
            temp = SubWord( temp );
        }
        w[ i ] = w[ i - NK ] ^ temp;
        i++;
    }
}

void aes_initialize(char* cipherkey, word w[Nb*(Nr+1)]){
    aes_initialize_sbox(sbox);
    aes_initialize_rcon(rcon);
    byte key[4*Nk] = {0};
    ckey2bkey(cipherkey,key);
    KeyExpansion(key,w,Nk);
}

void aes_cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]) {
    byte *state = (byte*)calloc( 4 * Nb, sizeof(byte) );
    aes_covert_io_state( in, state );
    AddRoundKey( state, &w[ 0 ] ); // See Sec. 5.1.4
    for ( uint8_t round = 1; round <= Nr-1; round++ ) {
        SubBytes( state ); // See Sec. 5.1.1
        ShiftRows( state ); // See Sec. 5.1.2
        MixColumns( state ); // See Sec. 5.1.3
        AddRoundKey( state, &w[ round*Nb ] );
    }
    SubBytes( state );
    ShiftRows( state );
    AddRoundKey( state, &w[ Nr*Nb ] );
    aes_covert_io_state( state, out );
}