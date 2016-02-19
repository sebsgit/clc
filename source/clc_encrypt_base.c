#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "clc_encrypt_base.h"

#ifdef CLC_WITH_SSE
	#include "xmmintrin.h"
#endif

unsigned char clc_s_box[256] = 
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static unsigned char clc_s_box_inv[256] = 
{
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static unsigned char clc_E_tab[256] = {
	0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35,
	0x5F, 0xE1, 0x38, 0x48, 0xD8, 0x73, 0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA,
	0xE5, 0x34, 0x5C, 0xE4, 0x37, 0x59, 0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70, 0x90, 0xAB, 0xE6, 0x31,
	0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x4F, 0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD,
	0x4C, 0xD4, 0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08, 0x18, 0x28, 0x78, 0x88,
	0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F, 0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76, 0x9A,
	0xB5, 0xC4, 0x57, 0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6, 0x61, 0xA3,
	0xFE, 0x19, 0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F, 0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0,
	0xFB, 0x16, 0x3A, 0x4E, 0xD2, 0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F, 0x41,
	0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0, 0x5B, 0xED, 0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75,
	0x9F, 0xBA, 0xD5, 0x64, 0xAC, 0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC, 0xDF, 0x7A, 0x8E, 0x89, 0x80,
	0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F, 0xB1, 0xC8, 0x43, 0xC5, 0x54,
	0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA,
	0x45, 0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42, 0xC6, 0x51, 0xF3, 0x0E,
	0x12, 0x36, 0x5A, 0xEE, 0x29, 0x7B, 0x8D, 0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17,
	0x39, 0x4B, 0xDD, 0x7C, 0x84, 0x97, 0xA2, 0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7, 0x52, 0xF6, 0x01
};

static unsigned char clc_L_tab[256] = {
	0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B, 0x68, 0x33, 0xEE, 0xDF, 0x03,
	0x64, 0x04, 0xE0, 0x0E, 0x34, 0x8D, 0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1,
	0x7D, 0xC2, 0x1D, 0xB5, 0xF9, 0xB9, 0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72, 0x9A, 0xC9, 0x09, 0x78,
	0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1, 0x24, 0x12, 0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E,
	0x96, 0x8F, 0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1, 0x40, 0x46, 0x83, 0x38,
	0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62, 0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91, 0x10,
	0x7E, 0x6E, 0x48, 0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85, 0x3D, 0xBA,
	0x2B, 0x79, 0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E, 0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57,
	0xAF, 0x58, 0xA8, 0x50, 0xF4, 0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD, 0xE8,
	0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5, 0x59, 0xCB, 0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0,
	0x7F, 0x0C, 0xF6, 0x6F, 0x17, 0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F, 0x2D, 0xA4, 0x76, 0x7B, 0xB7,
	0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1, 0x6C, 0xAA, 0x55, 0x29, 0x9D,
	0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE, 0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1,
	0x53, 0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D, 0x56, 0xF2, 0xD3, 0xAB,
	0x44, 0x11, 0x92, 0xD9, 0x23, 0x20, 0x2E, 0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5,
	0x67, 0x4A, 0xED, 0xDE, 0xC5, 0x31, 0xFE, 0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0, 0xF7, 0x70, 0x07
};

static unsigned char clc_Rcon_tab[16] = {
	0x00, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 
	0x80, 0x1B, 0x36, 0x6C, 
	0xD8, 0xAB, 0x4D, 0x9A
};

static unsigned char clc_get_b_m(const clc_bytes_16 * x, short rn, short cn){
	assert( x && cn>-1 && cn<4 && rn>-1 && rn<4 );
	return x->b[rn+cn*4];
}

static void clc_set_b_m(short rn, short cn, clc_bytes_16 * x, unsigned char v){
	assert( x && cn>-1 && cn<4 && rn>-1 && rn<4 );
	x->b[rn+cn*4] = v;
}

static void clc_xor_16(unsigned char * b1, unsigned char * b2){
	#ifdef CLC_WITH_SSE
		__m128 bytes_sse = _mm_loadu_ps((const float*)b1);
		__m128 key_sse = _mm_loadu_ps((const float*)b2);
		__m128 xor_sse = _mm_xor_ps(bytes_sse,key_sse);
		_mm_storeu_ps((float *)b1,xor_sse);
	#else
		short i;
		for( i=0 ; i<16 ; ++i ){
			b1[i] ^= b2[i];
		}
	#endif
}


void clc_sub_bytes( clc_bytes_16 * x ){
	short i;
	for(i=0 ; i<16 ; ++i){
		x->b[i] = clc_s_box[ x->b[i] ];
	}
}

void clc_sub_bytes_rev( clc_bytes_16 * x ){
	short i;
	for(i=0 ; i<16 ; ++i){
		x->b[i] = clc_s_box_inv[ x->b[i] ];
	}
}

void clc_shift_row_right(short rn, clc_bytes_16 * x){
	const unsigned short tmp = clc_get_b_m(x,rn,0);
	clc_set_b_m( rn,0,x, clc_get_b_m(x,rn,3) );
	clc_set_b_m( rn,3,x, clc_get_b_m(x,rn,2) );
	clc_set_b_m( rn,2,x, clc_get_b_m(x,rn,1) );
	clc_set_b_m( rn,1,x, tmp );
	
}

void clc_shift_row_left(short rn, clc_bytes_16 * x){
	const unsigned short tmp = clc_get_b_m(x,rn,0);
	clc_set_b_m( rn,0,x, clc_get_b_m(x,rn,1) );
	clc_set_b_m( rn,1,x, clc_get_b_m(x,rn,2) );
	clc_set_b_m( rn,2,x, clc_get_b_m(x,rn,3) );
	clc_set_b_m( rn,3,x, tmp );
}

void clc_shift_row_left_n(short rn, clc_bytes_16 * x, short c){
	short i;
	for(i=0 ; i<c ; ++i){
		clc_shift_row_left(rn,x);
	}
}

void clc_shift_row_right_n(short rn, clc_bytes_16 * x, short c){
	short i;
	for(i=0 ; i<c ; ++i){
		clc_shift_row_right(rn,x);
	}
}

void clc_shift_row(clc_bytes_16 * x){
	short i;
	for(i=1 ; i<4 ; ++i){
		clc_shift_row_left_n(i,x,i);
	}
}

void clc_shift_row_rev( clc_bytes_16 * x ){
	short i;
	for(i=1 ; i<4 ; ++i){
		clc_shift_row_right_n(i,x,i);
	}
}

unsigned char clc_mult_L(unsigned char b1, unsigned char b2){
	unsigned int res = clc_L_tab[b1] + clc_L_tab[b2];
	if( b1 == 0x01 ) return b2;
	if( b2 == 0x01 ) return b1;
	if( b1 == 0x00 || b2 == 0x00 ) return 0x00;
	if( res > 0xFF ){
		res -= 0xFF;
	}
	return clc_E_tab[(unsigned char)res];
}

void clc_mix_column(short cn, clc_bytes_16 * x){
	unsigned char col[4];
	memcpy(col,(x->b + cn*4),4);
	x->b[0+cn*4] = clc_mult_L(0x02,col[0])^clc_mult_L(0x03,col[1])^clc_mult_L(0x01,col[2])^clc_mult_L(0x01,col[3]);
	x->b[1+cn*4] = clc_mult_L(0x01,col[0])^clc_mult_L(0x02,col[1])^clc_mult_L(0x03,col[2])^clc_mult_L(0x01,col[3]);
	x->b[2+cn*4] = clc_mult_L(0x01,col[0])^clc_mult_L(0x01,col[1])^clc_mult_L(0x02,col[2])^clc_mult_L(0x03,col[3]);
	x->b[3+cn*4] = clc_mult_L(0x03,col[0])^clc_mult_L(0x01,col[1])^clc_mult_L(0x01,col[2])^clc_mult_L(0x02,col[3]);
}

void clc_mix_column_rev(short cn, clc_bytes_16 * x){
	unsigned char col[4];
	memcpy(col,(x->b + cn*4),4);
	x->b[0+cn*4] = clc_mult_L(0x0E,col[0])^clc_mult_L(0x0B,col[1])^clc_mult_L(0x0D,col[2])^clc_mult_L(0x09,col[3]);
	x->b[1+cn*4] = clc_mult_L(0x09,col[0])^clc_mult_L(0x0E,col[1])^clc_mult_L(0x0B,col[2])^clc_mult_L(0x0D,col[3]);
	x->b[2+cn*4] = clc_mult_L(0x0D,col[0])^clc_mult_L(0x09,col[1])^clc_mult_L(0x0E,col[2])^clc_mult_L(0x0B,col[3]);
	x->b[3+cn*4] = clc_mult_L(0x0B,col[0])^clc_mult_L(0x0D,col[1])^clc_mult_L(0x09,col[2])^clc_mult_L(0x0E,col[3]);
}

void clc_mix_columns( clc_bytes_16 * x ){
	short i;
	for(i=0 ;i<4 ; ++i){
		clc_mix_column(i,x);
	}
}

void clc_mix_columns_rev( clc_bytes_16 * x ){
	short i;
	for(i=0 ;i<4 ; ++i){
		clc_mix_column_rev(i,x);
	}
}

static void clc_rot_sub_word(unsigned char* bp, const unsigned char rcon) {
	const unsigned char tmp = bp[0];
	bp[0] = clc_s_box[ bp[1] ] ^ rcon;
	bp[1] = clc_s_box[ bp[2]] ;
	bp[2] = clc_s_box[ bp[3] ];
	bp[3] = clc_s_box[ tmp ];
}

void clc_key_sched_core( unsigned char * b_in, short i ){
	clc_rot_sub_word(b_in, clc_Rcon_tab[i]);
}

short clc_rounds( short key_len ){
	if( key_len == 16 ){
		return 10;
	} else if( key_len == 24 ){
		return 12;
	} else if( key_len == 32 ){
		return 14;
	} else{
		assert(0 && "invalid key length!");
	}
	return -1;
}

void clc_add_round_key( clc_bytes_16 * x , unsigned char * key, short n_round ){
	clc_xor_16(x->b,key+n_round*16);
}

void clc_add_round_key_rev( clc_bytes_16 * x , unsigned char * key, short n_round, int key_len ){
	clc_xor_16(x->b,key+key_len-n_round*16);
}

void clc_encrypt( clc_bytes_16 * x, unsigned char * key, short n_rounds ){
	short i;
	clc_add_round_key(x,key,0);
	for( i=1 ; i<n_rounds ; ++i ){
		clc_sub_bytes(x);
		clc_shift_row(x);
		clc_mix_columns(x);
		clc_add_round_key(x,key,i);
	}
	clc_sub_bytes(x);
	clc_shift_row(x);
	clc_add_round_key(x,key,n_rounds);
}

void clc_decrypt( clc_bytes_16 * x, unsigned char * key, short n_rounds, int key_size ){
	short i;
	clc_add_round_key_rev(x,key,0,key_size);
	for( i=1 ; i<n_rounds ; ++i ){
		clc_shift_row_rev(x);
		clc_sub_bytes_rev(x);
		clc_add_round_key_rev(x,key,i,key_size);
		clc_mix_columns_rev(x);
	}
	clc_shift_row_rev(x);
	clc_sub_bytes_rev(x);
	clc_add_round_key_rev(x,key,n_rounds,key_size);
}

void clc_init_key(unsigned char * key, const unsigned char * data, int data_len){
	memcpy(key,data,data_len);
}
