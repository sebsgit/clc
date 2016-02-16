#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "clc_encrypt_16.h"
#include "clc_encrypt_24.h"
#include "clc_encrypt_32.h"
#include "clc_md5.h"
#include "clc_sha1.h"

void test_16(int num_test){
	int i,j;
	clc_bytes_16 b1, b2;
	clc_key_exp_16 key;
	srand(time(0));
	for(i=0 ; i<num_test ; ++i){
		for(j=0 ; j<16 ; ++j){
			key.b[j] = rand()%256;
			b1.b[j] = rand()%256;
		}
		clc_cpy_b(&b1,&b2);
		clc_expand_key_16(&key);
		clc_encrypt_16(&b1,&key);
		clc_decrypt_16(&b1,&key);
		assert( clc_test_eq(&b1,&b2) );
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b%i/%i...",i+1,num_test);
	}
}

void test_24(int num_test){
	int i,j;
	clc_bytes_16 b1, b2;
	clc_key_exp_24 key;
	srand(time(0));
	for(i=0 ; i<num_test ; ++i){
		for(j=0 ; j<24 ; ++j){
			key.b[j] = rand()%256;
			if(j<16)
				b1.b[j] = rand()%256;
		}
		clc_cpy_b(&b1,&b2);
		clc_expand_key_24(&key);
		clc_encrypt_24(&b1,&key);
		clc_decrypt_24(&b1,&key);
		assert( clc_test_eq(&b1,&b2) );
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b%i/%i...",i+1,num_test);
	}
}

void test_32(int num_test){
	int i,j;
	clc_bytes_16 b1, b2;
	clc_key_exp_32 key;
	srand(time(0));
	for(i=0 ; i<num_test ; ++i){
		for(j=0 ; j<32 ; ++j){
			key.b[j] = rand()%256;
			if(j<16)
				b1.b[j] = rand()%256;
		}
		clc_cpy_b(&b1,&b2);
		clc_expand_key_32(&key);
		clc_encrypt_32(&b1,&key);
		clc_decrypt_32(&b1,&key);
		assert( clc_test_eq(&b1,&b2) );
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b%i/%i...",i+1,num_test);
	}
}

void test(){
	clc_bytes_16 b1;
	clc_key_exp_16 key;
	
	key.b[0] = 0x0f;
	key.b[1] = 0x15;
	key.b[2] = 0x71;
	key.b[3] = 0xc9;
    key.b[4] = 0x47;
    key.b[5] = 0xd9;
    key.b[6] = 0xe8;
    key.b[7] = 0x59;
    key.b[8] = 0x0c;
    key.b[9] = 0xb7;
    key.b[10] = 0xad; 
    key.b[11] = 0xd6;
    key.b[12] = 0xaf;
    key.b[13] = 0x7f;
    key.b[14] = 0x67;
    key.b[15] = 0x98;
    
    memset(b1.b,0x61,16);
	clc_print_b_mat(&b1);
	
	clc_expand_key_16(&key);
	clc_encrypt_16(&b1,&key);
	printf("\n");
	clc_print_b_mat(&b1);
	
	clc_decrypt_16(&b1,&key);
	printf("\n");
	clc_print_b_mat(&b1);
}

int main(int argc, char ** argv){
	const int n = 2000;
	clc_bytes_16 b;
	clc_bytes_20 b20;
	
	test();
	test_16(n);
	test_24(n);
	test_32(n);
	printf("\n");
	
	clc_md5((const unsigned char*)"a text to md5", strlen("a text to md5"), &b);
	unsigned char result_md5[] = { 0xf5, 0xbf, 0x69, 0x72, 0x1c, 0x97, 0xea, 0x67, 0xb3, 0xc3, 0xc6, 0x31, 0x81, 0xca, 0xbf, 0x90 };
	assert(memcmp(&b, result_md5, 16) == 0);
	
	clc_sha1((const unsigned char*)"text to sha1 test",strlen("text to sha1 test"),&b20);
	unsigned char result_sha1[] = { 0x4c, 0xab, 0x60, 0x2c, 0x07, 0xe1, 0xa5, 0x7e, 0x95, 0xe9, 0xba, 0xe3, 0xaa, 0x29, 0x81, 0xa8, 0x4d, 0xab, 0x73, 0xc1 };
	assert(memcmp(&b20, result_sha1, 20) == 0);
	return 0;
}

