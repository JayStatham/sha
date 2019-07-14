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
#include "sha256.h"
#include "sha-byteorder.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//macros
#define	CHUNK_SIZE		(64)
#define	PADDING_MOD		(56)
//padding size: [1, 64] bytes
#define	_sha256_filling_size(x)	(((x) % CHUNK_SIZE) < PADDING_MOD ? \
		(PADDING_MOD - ((x) % CHUNK_SIZE)): CHUNK_SIZE)
#define	_sha256_padding_size(x)	(_sha256_filling_size(x) + 8)
#define	_sha256_msg_size_be(x)	_sha_be64(x)
#define	_sha256_file_chunk_size(x)	((x) + _sha256_padding_size(x))
//round constants
static	sha256_word		round_constants[] =
{
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void init_sha256_hash(struct sha256_hash *sh)
{
	sh->hash[0] = 0x6a09e667;
	sh->hash[1] = 0xbb67ae85;
	sh->hash[2] = 0x3c6ef372;
	sh->hash[3] = 0xa54ff53a;
	sh->hash[4] = 0x510e527f;
	sh->hash[5] = 0x9b05688c;
	sh->hash[6] = 0x1f83d9ab;
	sh->hash[7] = 0x5be0cd19;
}

static void process_chunk(struct sha256_hash *sh, void* chunk)
{
	//break chunk into sixteen 32-bit big-endian words w[0..15]
	sha256_word w[64] = {0};
	sha256_word *ck = (sha256_word*)chunk;

	for (int n = 0; n < 16; ++n)
	{
		w[n] = _sha_be32(ck[n]);
	}
	//Extend the sixteen 32-bit words into sixty-four 32-bit words:
	for (int i = 16; i < 64; ++i)
	{
		sha256_word s0 = _sha_right_rotate32(w[i - 15], 7) ^ _sha_right_rotate32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		sha256_word s1 = _sha_right_rotate32(w[i - 2], 17) ^ _sha_right_rotate32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	sha256_word a = sh->hash[0];
	sha256_word b = sh->hash[1];
	sha256_word c = sh->hash[2];
	sha256_word d = sh->hash[3];
	sha256_word e = sh->hash[4];
	sha256_word f = sh->hash[5];
	sha256_word g = sh->hash[6];
	sha256_word h = sh->hash[7];

	for (int i = 0; i < 64; ++i)
	{
		sha256_word s0 = _sha_right_rotate32(a, 2) ^ _sha_right_rotate32(a, 13) ^ _sha_right_rotate32(a, 22);
		sha256_word maj = (a & b) ^ (a & c) ^ (b & c);
		sha256_word t2 = s0 + maj;
		sha256_word s1 = _sha_right_rotate32(e, 6) ^ _sha_right_rotate32(e, 11) ^ _sha_right_rotate32(e, 25);
		sha256_word ch = (e & f) ^ ((~e) & g);
		sha256_word t1 = h + s1 + ch + round_constants[i] + w[i];
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	sh->hash[0] += a;
	sh->hash[1] += b;
	sh->hash[2] += c;
	sh->hash[3] += d;
	sh->hash[4] += e;
	sh->hash[5] += f;
	sh->hash[6] += g;
	sh->hash[7] += h;
}

bool sha256_checksum(void* buf, size_t size, struct sha256_hash* hash)
{
	size_t	msg_bit_size = size * 8;
	size_t	sha256_buffer_size = size + _sha256_padding_size(size);
	char*	pbuf = (char*)malloc(sha256_buffer_size);

	if (pbuf == NULL)
	{
		return false;
	}
	// make chunk buffer
	memcpy(pbuf, buf, size);
	// filling 1bit, 0s...
	pbuf[size] = 0x80;
	memset(pbuf + 1 + size, 0, _sha256_filling_size(size) - 1);
	// filling buffer size in bits to 64bits Big-Endian value
	*((uint64_t*)(pbuf + _sha256_filling_size(size) + size)) = _sha256_msg_size_be(msg_bit_size);
	init_sha256_hash(hash);
	
	for (size_t s = 0; s < sha256_buffer_size; s += CHUNK_SIZE)
	{
		process_chunk(hash, &pbuf[s]);
	}

	free(pbuf);
	return true;
}

bool sha256_file_checksum(const char* filepath, struct sha256_hash* hash)
{
	FILE	*fp = NULL;
	size_t	rd = 0;
	size_t	msg_bit_size = 0;
	char	sha256_buffer[_sha256_file_chunk_size(512)] = { 0 };

	fp = fopen(filepath, "r");

	if (fp == NULL)
	{
		return false;
	}
	
	init_sha256_hash(hash);

	while (true)
	{
		rd = fread(sha256_buffer, 1, 512, fp);

		if (rd < 1)
		{
			break;
		}
		// filling 1bits, 0s...
		sha256_buffer[rd] = 0x80;
		memset(sha256_buffer + 1 + rd, 0, _sha256_filling_size(rd) - 1);
		// filling buffer size in bits to 64bits Big-Endian value
		msg_bit_size = rd * 8;
		*((uint64_t*)(sha256_buffer + _sha256_filling_size(rd) + rd)) = _sha256_msg_size_be(msg_bit_size);
		size_t	msg_size = rd + _sha256_padding_size(rd);

		for (size_t s = 0; s < msg_size; s += CHUNK_SIZE)
		{
			process_chunk(hash, &sha256_buffer[s]);
		}
	}

	fclose(fp);
	return true;
}

bool sha256_hash_to_hexstr(struct sha256_hash* hash, char* str, size_t ssize, bool uppercase)
{
	int	wt = 0;

	if (ssize < 65)
	{
		return false;
	}

	for (int i = 0; (i < 8) && (ssize - wt > 0); ++ i)
	{
		wt += snprintf(str + wt, ssize - wt, 
			((uppercase == false) ? "%.2x%.2x%.2x%.2x" : "%.2X%.2X%.2X%.2X"), 
			(hash->hash[i] & 0xff000000) >> 24,
			(hash->hash[i] & 0x00ff0000) >> 16,
			(hash->hash[i] & 0x0000ff00) >> 8,
			(hash->hash[i] & 0x000000ff)
		);
	}

	return true;
}