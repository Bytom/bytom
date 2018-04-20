#ifndef _C_SIMD_TENSOR_H_
#define _C_SIMD_TENSOR_H_

#ifdef __cplusplus
extern "C" {
#endif
	#include <stdint.h>

	int SimdTs(uint8_t blockheader[32], uint8_t seed[32], uint8_t res[32]);

#ifdef __cplusplus
}
#endif

#endif
