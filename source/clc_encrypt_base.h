#ifndef _CLC_ENCRYPT_BASE_H_
#define _CLC_ENCRYPT_BASE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "clc_bytes.h"

extern void clc_sub_bytes( clc_bytes_16 * x );
extern void clc_sub_bytes_rev( clc_bytes_16 * x );
extern void clc_shift_row_right(short rn, clc_bytes_16 * x);
extern void clc_shift_row_left(short rn, clc_bytes_16 * x);
extern void clc_shift_row_left_n(short rn, clc_bytes_16 * x, short c);
extern void clc_shift_row_right_n(short rn, clc_bytes_16 * x, short c);
extern void clc_shift_row(clc_bytes_16 * x);
extern void clc_shift_row_rev( clc_bytes_16 * x );
extern unsigned char clc_mult_L(unsigned char b1, unsigned char b2);
extern void clc_mix_column(short cn, clc_bytes_16 * x);
extern void clc_mix_column_rev(short cn, clc_bytes_16 * x);
extern void clc_mix_columns( clc_bytes_16 * x );
extern void clc_mix_columns_rev( clc_bytes_16 * x );

extern void clc_key_sched_core( unsigned char * b_in, short i );

extern void clc_init_key( unsigned char * key, const unsigned char * data, int data_len );
extern void clc_add_round_key( clc_bytes_16 * x, unsigned char * key_b, short n_round );
extern void clc_add_round_key_rev( clc_bytes_16 * x, unsigned char * key_b, short n_round, int key_size );
extern void clc_encrypt( clc_bytes_16 * x, unsigned char * key, short n_rounds );
extern void clc_decrypt( clc_bytes_16 * x, unsigned char * key, short n_rounds, int key_size );

extern short clc_rounds( short key_len );

#ifdef __cplusplus
}
#endif

#endif
