#ifndef _CLC_ENCRYPT_32_H_
#define _CLC_ENCRYPT_32_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "clc_bytes.h"

typedef struct {
	unsigned char b[240];
} clc_aes_key_256;

extern void clc_init_key_32( clc_aes_key_256 * key, const unsigned char * data, int data_len );
extern void clc_expand_key_32( clc_aes_key_256 * key );
extern void clc_print_key_32( const clc_aes_key_256 * key );

extern void clc_encrypt_32( clc_bytes_16 * x, clc_aes_key_256 * key );
extern void clc_decrypt_32( clc_bytes_16 * x, clc_aes_key_256 * key );

void clc_encrypt_data_32( unsigned char * in, clc_aes_key_256 * key, long data_len );
void clc_decrypt_data_32( unsigned char * in, clc_aes_key_256 * key, long data_len );

#ifdef __cplusplus
}
#endif

#endif
