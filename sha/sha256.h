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
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
//types
typedef	uint32_t	sha256_word;
//SHA256 hash: Big-Endian
//digest = hash = h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
struct sha256_hash
{
	sha256_word	hash[8];
};
// sha256_checksum
// caculate SHA256 checksum
//   buf*	buffer in bytes
//	size	unit of byte
bool sha256_checksum(void* buf, size_t size, struct sha256_hash* hash);
bool sha256_file_checksum(const char* filepath, struct sha256_hash* hash);
bool sha256_hash_to_hexstr(struct sha256_hash* hash, char* str, size_t ssize, bool uppercase);

#ifdef __cplusplus
}
#endif