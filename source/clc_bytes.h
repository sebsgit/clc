#ifndef _CLC_BYTES_H_
#define _CLC_BYTES_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _clc_bytes_16{
	unsigned char b[16];
} clc_bytes_16;

typedef struct _clc_bytes_20{
	unsigned char b[20];
} clc_bytes_20;

extern unsigned char clc_get_b_m(const clc_bytes_16 * x, short rn, short cn);
extern void clc_set_b_m(short rn, short cn, clc_bytes_16 * x, unsigned char v);

/*!
 * \brief returns 1 if *x1 == *x2, else return 0
 */
extern short clc_test_eq( const clc_bytes_16 * x1, const clc_bytes_16 * x2 );
extern void clc_print_b(const clc_bytes_16 * x);
extern void clc_print_b_mat(const clc_bytes_16 * x);

extern void clc_xor_16(unsigned char * b1, unsigned char * b2);

extern void clc_print_b_20(const clc_bytes_20 * x);

#ifdef __cplusplus
}
#endif

#endif
