#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "clc_bytes.h"

void clc_print_b(const clc_bytes_16 * x){
	short i=0;
	for(i=0 ; i<16 ; ++i){
		printf("%x ",x->b[i]);
	}
	printf("\n");
}

void clc_print_b_mat(const clc_bytes_16 * x){
	short r=0, c=0;
	for(r=0 ; r<4 ; ++r){
		for(c=0 ; c<4 ; ++c){
			printf("%x ",x->b[r + c * 4]);
		}
		printf("\n");
	}
	printf("\n");
}

void clc_print_b_20(const clc_bytes_20 * x){
	short i=0;
	for(i=0 ; i<20 ; ++i){
		printf("%x ",x->b[i]);
	}
	printf("\n");
}
