#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "clc_aes.h"
#include "clc_encrypt_base.h"

void clc_print_key_24( const clc_aes_key_192 * key ){
	short i;
	for( i=0 ; i<208 ; ++i ){
		printf("%x ",key->b[i]);
		if(i>0 && i%16 == 0) printf("\n");
	}
	printf("\n");
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

void clc_encrypt_24( clc_bytes_16 * x, clc_aes_key_192 * key ){
	clc_encrypt(x,key->b,12);
}

void clc_decrypt_24( clc_bytes_16 * x, clc_aes_key_192 * key ){
	clc_decrypt(x,key->b,12,192);
}
