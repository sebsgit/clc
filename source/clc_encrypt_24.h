#ifndef _CLC_ENCRYPT_24_H_
#define _CLC_ENCRYPT_24_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "clc_bytes.h"

typedef struct {
	unsigned char b[208];
} clc_aes_key_192;

extern void clc_init_key_24( clc_aes_key_192 * key, const unsigned char * data, int data_len );
extern void clc_expand_key_24( clc_aes_key_192 * key );
extern void clc_print_key_24( const clc_aes_key_192 * key );

extern void clc_encrypt_24( clc_bytes_16 * x, clc_aes_key_192 * key );
extern void clc_decrypt_24( clc_bytes_16 * x, clc_aes_key_192 * key );

#ifdef __cplusplus
}
#endif

#endif
