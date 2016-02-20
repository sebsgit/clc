#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "clc_encrypt_16.h"
#include "clc_encrypt_base.h"

void clc_print_key_16( const clc_aes_key_128 * key ){
	short i;
	for( i=0 ; i<176 ; ++i ){
		printf("%x ",key->b[i]);
		if(i>0 && i%15 == 0) printf("\n");
	}
	printf("\n");
}

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

void clc_encrypt_16( clc_bytes_16 * x, clc_aes_key_128 * key ){
	clc_encrypt(x,key->b,10);
}

void clc_decrypt_16( clc_bytes_16 * x, clc_aes_key_128 * key ){
	clc_decrypt(x,key->b,10,160);
}
