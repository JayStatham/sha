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
#include <stddef.h>

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
// sha256_file_checksum
// caculate SHA256 checksum from files
//   filepath  the path of file
bool sha256_file_checksum(const char* filepath, struct sha256_hash* hash);
// sha256_hash_to_str
//	convert sha256_hash to string format
//		hash	the sha256_hash pointer
//		str		the string for output
//		ssize	the size of string
//		fmt		the formula of the string, ex:
//				hex		aabbccddeeff0011	(lowercase)
//				h:e:x	aa:bb:cc:dd:...
//				h-e-x	aa-bb-cc-dd:...
//				HEX		AABBCCDDEEFF0011	(uppercase)
//				H:E:X	AA:BB:CC:DD:EE:...
//				H-E-X	AA-BB-CC-DD-EE:...
bool sha256_hash_to_str(struct sha256_hash* hash, char* str, size_t ssize, const char *fmt);

#ifdef __cplusplus
}
#endif