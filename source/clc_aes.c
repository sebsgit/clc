#include "clc_aes.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "clc_aes.h"
#include "clc_encrypt_base.h"

extern unsigned char clc_s_box[256];

static void clc_print_key_base(const unsigned char* key, const short size) {
	short i;
	for( i=0 ; i<size ; ++i ){
		printf("%x ",key[i]);
		if(i>0 && i%16 == 0) printf("\n");
	}
	printf("\n");
}

void clc_print_key_16( const clc_aes_key_128 * key ){ clc_print_key_base(key->b, 176); }
void clc_print_key_24( const clc_aes_key_192 * key ){ clc_print_key_base(key->b, 208); }
void clc_print_key_32( const clc_aes_key_256 * key ){ clc_print_key_base(key->b, 240); }

void clc_init_key_16( clc_aes_key_128 * key, const unsigned char * data, int data_len ){
	assert(data_len>0 && data_len<=16 && "FAIL: data length must be [1,16] !");
	clc_init_key(key->b,data,data_len);
	if(data_len<16){
		memset(key->b+data_len, 0, 16-data_len );
	}
}

void clc_expand_key_16( clc_aes_key_128 * key ){
	unsigned char buff[4];
	unsigned char p = 16;
	unsigned short i=1;
	unsigned char a;
	while(p < 176) {
		memcpy(buff, (key->b+p-4), 4);
		if(p % 16 == 0){
			clc_key_sched_core(buff,i);
			i++;
		}
		for(a = 0; a < 4; a++) {
			key->b[p] = key->b[p - 16] ^ buff[a];
			++p;
		}
	}
}


void clc_init_key_24( clc_aes_key_192 * key, const unsigned char * data, int data_len ){
	assert(data_len>0 && data_len<=24 && "FAIL: data length must be [1,24] !");
	clc_init_key(key->b,data,data_len);
	if(data_len<24){
		memset(key->b+data_len, 0, 24-data_len );
	}
}

void clc_expand_key_24( clc_aes_key_192 * key ){
	unsigned char buff[4];
	unsigned char p = 24;
	unsigned short i=1;
	unsigned char a;
	while(p < 208) {
		memcpy(buff, (key->b+p-4), 4);
		if(p % 24 == 0){
			clc_key_sched_core(buff,i);
			i++;
		}
		for(a = 0; a < 4; a++) {
			key->b[p] = key->b[p - 24] ^ buff[a];
			++p;
		}
	}
}

void clc_init_key_32( clc_aes_key_256 * key, const unsigned char * data, int data_len ){
	assert(data_len>0 && data_len<=32 && "FAIL: data length must be [1,32] !");
	clc_init_key(key->b,data,data_len);
	if(data_len<32){
		memset(key->b+data_len, 0, 32-data_len );
	}
}

void clc_expand_key_32( clc_aes_key_256 * key ){
	unsigned char buff[4];
	unsigned char p = 32;
	unsigned short i=1;
	unsigned char a;
	while(p < 240) {
		memcpy(buff, (key->b+p-4), 4);
		if(p % 32 == 0){
			clc_key_sched_core(buff,i);
			i++;
		}
		if(p % 32 == 16) {
			for(a = 0; a < 4; a++) 
				buff[a] = clc_s_box[ buff[a] ];
		}
		for(a = 0; a < 4; a++) {
			key->b[p] = key->b[p - 32] ^ buff[a];
			++p;
		}
	}
}

void clc_encrypt_16( clc_bytes_16 * x, clc_aes_key_128 * key ){ clc_encrypt(x,key->b,10); }
void clc_decrypt_16( clc_bytes_16 * x, clc_aes_key_128 * key ){ clc_decrypt(x,key->b,10,160); }
void clc_encrypt_24( clc_bytes_16 * x, clc_aes_key_192 * key ){ clc_encrypt(x,key->b,12); }
void clc_decrypt_24( clc_bytes_16 * x, clc_aes_key_192 * key ){ clc_decrypt(x,key->b,12,192); }
void clc_encrypt_32( clc_bytes_16 * x, clc_aes_key_256 * key ){ clc_encrypt(x,key->b,14); }
void clc_decrypt_32( clc_bytes_16 * x, clc_aes_key_256 * key ){ clc_decrypt(x,key->b,14,224); }
