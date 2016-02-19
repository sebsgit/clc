#ifndef _CLC_BYTES_H_
#define _CLC_BYTES_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned char b[16];
} clc_bytes_16;

typedef struct {
	unsigned char b[20];
} clc_bytes_20;

extern void clc_print_b(const clc_bytes_16 * x);
extern void clc_print_b_mat(const clc_bytes_16 * x);

extern void clc_print_b_20(const clc_bytes_20 * x);

#ifdef __cplusplus
}
#endif

#endif
