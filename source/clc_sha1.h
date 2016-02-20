#ifndef _CLC_SHA_1_H_
#define _CLC_SHA_1_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "clc_bytes.h"

extern void clc_sha1( const unsigned char * data, long data_len, clc_bytes_20 * out );

#ifdef __cplusplus
}
#endif

#endif
