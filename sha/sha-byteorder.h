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
#pragma once
#include <stdint.h>
#include <stddef.h>
// swap memory byteorder
#define	_sha_swap16(x)	((((unsigned short)(x) & 0xff00) >> 8) | (((unsigned short)(x) & 0x00ff) << 8))
#define	_sha_swap32(x)	((((unsigned int)(x) & 0xff000000) >> 24) | \
						(((unsigned int)(x) & 0x00ff0000) >> 8) | \
						(((unsigned int)(x) & 0x0000ff00) << 8) | \
						(((unsigned int)(x) & 0x000000ff) << 24))
#define	_sha_swap64(x)	(((uint64_t)_sha_swap32((uint64_t)(x) & 0xffffffff) << 32) | \
						_sha_swap32(((uint64_t)(x) >> 32) & 0xffffffff))
#define	_sha_swap128(x)	(swap128(x))
// byteorder by arch. Decide dynamic is better!
#if _MSC_VER
//host is LE
#define	_SHA_BYTE_ODER_LE	(1)
#define	_SHA_BYTE_ODER_BE	(0)
#define	_sha_be16(x)	_sha_swap16(x)
#define	_sha_le16(x)	(x)
#define	_sha_be32(x)	_sha_swap32(x)
#define	_sha_le32(x)	(x)
#define	_sha_be64(x)	_sha_swap64(x)
#define	_sha_le64(x)	(x)
#define	_sha_be128(x)	_sha_swap128(x)
#define	_sha_le128(x)	(x)
#elif defined(__GNUC__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
//host is LE
#define	_SHA_BYTE_ODER_LE	(1)
#define	_SHA_BYTE_ODER_BE	(0)
#define	_sha_be16(x)	_sha_swap16(x)
#define	_sha_le16(x)	(x)
#define	_sha_be32(x)	_sha_swap32(x)
#define	_sha_le32(x)	(x)
#define	_sha_be64(x)	_sha_swap64(x)
#define	_sha_le64(x)	(x)
#define	_sha_be128(x)	_sha_swap128(x)
#define	_sha_le128(x)	(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
//host is BE
#define	_SHA_BYTE_ODER_LE	(0)
#define	_SHA_BYTE_ODER_BE	(1)
#define	_sha_be16(x)	(x)
#define	_sha_le16(x)	_sha_swap16(x)
#define	_sha_be32(x)	(x)
#define	_sha_le32(x)	_sha_swap32(x)
#define	_sha_be64(x)	(x)
#define	_sha_le64(x)	_sha_swap64(x)
#define	_sha_be128(x)	(x)
#define	_sha_le128(x)	_sha_swap128(x)
#else
//error endian
#endif
#endif

#define	_sha_left_rotate32(x, n)	(((uint32_t)(x) >> (32 - (n))) | \
									((uint32_t)(x) << (n)))
#define	_sha_right_rotate32(x, n)	(((uint32_t)(x) << (32 - (n))) | \
									(uint32_t)(x) >> (n))
#define	_sha_left_rotate64(x, n)	(((uint64_t)(x) >> (64 - (n))) | \
									((uint64_t)(x) << (n)))
#define	_sha_right_rotate64(x, n)	(((uint64_t)(x) << (64 - (n))) | \
									(uint64_t)(x) >> (n))

#ifdef __cplusplus
extern "C" {
#endif
    //type big int
    typedef struct _uint128_t {
		union
		{
			uint8_t		u8[16];
			uint64_t	u64[2];
		};
    }uint128_t;

	uint128_t swap128(uint128_t);
	uint128_t bit_shift_left64(uint64_t, size_t);
#ifdef __cplusplus
}
#endif