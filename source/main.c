#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "clc_encrypt.h"
#include "clc_hash.h"

static short clc_test_eq( const clc_bytes_16 * x1, const clc_bytes_16 * x2 ){
	return (0 == memcmp(x1->b,x2->b,16));
}

static void test_16(int num_test){
	int i,j;
	clc_bytes_16 b1, b2;
	clc_aes_key_128 key;
	srand(time(0));
	for(i=0 ; i<num_test ; ++i){
		for(j=0 ; j<16 ; ++j){
			key.b[j] = rand()%256;
			b1.b[j] = rand()%256;
		}
		memcpy(&b2, &b1, sizeof(b1));
		clc_expand_key_16(&key);
		clc_encrypt_16(&b1,&key);
		clc_decrypt_16(&b1,&key);
		assert( clc_test_eq(&b1,&b2) );
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b%i/%i...",i+1,num_test);
	}
}

static void test_24(int num_test){
	int i,j;
	clc_bytes_16 b1, b2;
	clc_aes_key_192 key;
	srand(time(0));
	for(i=0 ; i<num_test ; ++i){
		for(j=0 ; j<24 ; ++j){
			key.b[j] = rand()%256;
			if(j<16)
				b1.b[j] = rand()%256;
		}
		memcpy(&b2, &b1, sizeof(b1));
		clc_expand_key_24(&key);
		clc_encrypt_24(&b1,&key);
		clc_decrypt_24(&b1,&key);
		assert( clc_test_eq(&b1,&b2) );
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b%i/%i...",i+1,num_test);
	}
}

static void test_32(int num_test){
	int i,j;
	clc_bytes_16 b1, b2;
	clc_aes_key_256 key;
	srand(time(0));
	for(i=0 ; i<num_test ; ++i){
		for(j=0 ; j<32 ; ++j){
			key.b[j] = rand()%256;
			if(j<16)
				b1.b[j] = rand()%256;
		}

		memcpy(&b2, &b1, sizeof(b1));
		clc_expand_key_32(&key);
		clc_encrypt_32(&b1,&key);
		clc_decrypt_32(&b1,&key);
		assert( clc_test_eq(&b1,&b2) );
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b%i/%i...",i+1,num_test);
	}
}

static void validate_aes_16() {
	const unsigned char aes_key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	const unsigned char plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	const unsigned char expected_cipher[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
	const unsigned char plaintext2[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	const unsigned char key2[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	const unsigned char expected2[] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
	clc_aes_key_128 key;
	clc_bytes_16 data;
	memcpy(&key, aes_key, sizeof(key));
	memcpy(&data, plaintext, sizeof(data));
	clc_expand_key_16(&key);
	clc_encrypt_16(&data, &key);
	assert(memcmp(&data, expected_cipher, sizeof(data)) == 0);
	clc_decrypt_16(&data, &key);
	assert(memcmp(&data, plaintext, sizeof(data)) == 0);
	
	memcpy(&key, key2, sizeof(key));
	memcpy(&data, plaintext2, sizeof(data));
	clc_expand_key_16(&key);
	clc_encrypt_16(&data, &key);
	assert(memcmp(&data, expected2, sizeof(data)) == 0);
}

static void validate_aes_24() {
	const unsigned char plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	const unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	const unsigned char expected_cipher[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
	clc_aes_key_192 key24;
	clc_bytes_16 data;
	memcpy(&key24, key, sizeof(key24));
	clc_expand_key_24(&key24);
	memcpy(&data, plaintext, sizeof(data));
	clc_encrypt_24(&data, &key24);
	assert(memcmp(&data, expected_cipher, sizeof(data)) == 0);
	clc_decrypt_24(&data, &key24);
	assert(memcmp(&data, plaintext, sizeof(data)) == 0);
}

static void validate_aes_32() {
	const unsigned char plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	const unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const unsigned char expected_cipher[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
	clc_aes_key_256 key32;
	clc_bytes_16 data;
	memcpy(&key32, key, sizeof(key32));
	clc_expand_key_32(&key32);
	memcpy(&data, plaintext, sizeof(data));
	clc_encrypt_32(&data, &key32);
	assert(memcmp(&data, expected_cipher, sizeof(data)) == 0);
	clc_decrypt_32(&data, &key32);
	assert(memcmp(&data, plaintext, sizeof(data)) == 0);
}

int main(int argc, char ** argv){
	const int n = 2000;
	const unsigned char result_md5[] = { 0xf5, 0xbf, 0x69, 0x72, 0x1c, 0x97, 0xea, 0x67, 0xb3, 0xc3, 0xc6, 0x31, 0x81, 0xca, 0xbf, 0x90 };
	const unsigned char result_sha1[] = { 0x4c, 0xab, 0x60, 0x2c, 0x07, 0xe1, 0xa5, 0x7e, 0x95, 0xe9, 0xba, 0xe3, 0xaa, 0x29, 0x81, 0xa8, 0x4d, 0xab, 0x73, 0xc1 };
	clc_bytes_16 b;
	clc_bytes_20 b20;
	
	validate_aes_16();
	validate_aes_24();
	validate_aes_32();
	test_16(n);
	test_24(n);
	test_32(n);
	printf("\n");
	
	clc_md5((const unsigned char*)"a text to md5", strlen("a text to md5"), &b);
	assert(memcmp(&b, result_md5, 16) == 0);
	
	clc_sha1((const unsigned char*)"text to sha1 test",strlen("text to sha1 test"),&b20);
	assert(memcmp(&b20, result_sha1, 20) == 0);
	return 0;
}

