/*
The MIT License (MIT) 
Copyright © 2019 JStatham
Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the “Software”), to deal in 
 the Software without restriction, including without limitation the rights to use, 
 copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
 Software, and to permit persons to whom the Software is furnished to do so, subject 
 to the following conditions:
The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Date: 2019/7/14
 */
#include "sha-byteorder.h"

uint128_t swap128(uint128_t x)
{
	uint128_t y = {0};
	y.u8[0] = x.u8[15];
	y.u8[1] = x.u8[14];
	y.u8[2] = x.u8[13];
	y.u8[3] = x.u8[12];
	y.u8[4] = x.u8[11];
	y.u8[5] = x.u8[10];
	y.u8[6] = x.u8[9];
	y.u8[7] = x.u8[8];
	y.u8[8] = x.u8[7];
	y.u8[9] = x.u8[6];
	y.u8[10] = x.u8[5];
	y.u8[11] = x.u8[4];
	y.u8[12] = x.u8[3];
	y.u8[13] = x.u8[2];
	y.u8[14] = x.u8[1];
	y.u8[15] = x.u8[0];
	return y;
}

uint128_t bit_shift_left64(uint64_t x, size_t bits)
{
	uint128_t z = {0};
	uint64_t s = _sha_left_rotate64(x, bits);
	uint64_t m = 0;

	for (size_t i = 0; i < bits; ++ i)
	{
		m |= 1 << i;
	}

	s &= m;
#if _SHA_BYTE_ODER_LE
	z.u64[0] = x << bits;
	z.u64[1] <<= bits;
	z.u64[1] |= s;
#else
	z.u64[1] = x << bits;
	z.u64[0] <<= bits;
	z.u64[0] |= s;
#endif
	return z;
}