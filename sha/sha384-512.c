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
#include "sha384-512.h"
#include "sha-byteorder.h"
#include "sha-ulti.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//macros
#define	CHUNK_SIZE			(128)
#define	PADDING_MOD			(112)
//using to sha-calc, to replaced heap way(malloc)
#define	STACK_BUFFER_SIZE	(512)
//padding size: [1, 64] bytes
#define	_sha384_filling_size(x)	(((x) % CHUNK_SIZE) < PADDING_MOD ? \
		(PADDING_MOD - ((x) % CHUNK_SIZE)): CHUNK_SIZE)
#define	_sha384_padding_size(x)	(_sha384_filling_size(x) + 16)
#define	_sha384_msg_size_be(x)	_sha_be128(x)
#define	_sha384_file_chunk_size(x)	((x) + _sha384_padding_size(x))
//round constants
static	sha384_word		round_constants[] =
{
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static void init_sha384_hash(struct sha384_hash *sh)
{
	sh->hash[0] = 0xcbbb9d5dc1059ed8;
	sh->hash[1] = 0x629a292a367cd507;
	sh->hash[2] = 0x9159015a3070dd17;
	sh->hash[3] = 0x152fecd8f70e5939;
	sh->hash[4] = 0x67332667ffc00b31;
	sh->hash[5] = 0x8eb44a8768581511;
	sh->hash[6] = 0xdb0c2e0d64f98fa7;
	sh->hash[7] = 0x47b5481dbefa4fa4;
}

static void init_sha512_hash(struct sha512_hash *sh)
{
	sh->hash[0] = 0x6a09e667f3bcc908;
	sh->hash[1] = 0xbb67ae8584caa73b;
	sh->hash[2] = 0x3c6ef372fe94f82b;
	sh->hash[3] = 0xa54ff53a5f1d36f1;
	sh->hash[4] = 0x510e527fade682d1;
	sh->hash[5] = 0x9b05688c2b3e6c1f;
	sh->hash[6] = 0x1f83d9abfb41bd6b;
	sh->hash[7] = 0x5be0cd19137e2179;
}

static void process_chunk(struct sha384_hash *sh, void* chunk)
{
	//break chunk into sixteen 64-bit big-endian words w[0..15]
	sha384_word w[80] = {0};
	sha384_word *ck = (sha384_word*)chunk;

	for (int n = 0; n < 16; ++n)
	{
		w[n] = _sha_swap64(ck[n]);
	}
	//Extend the 16 64-bit words into 80 64-bit words:
	for (int i = 16; i < 80; ++i)
	{
		sha384_word s0 = _sha_right_rotate64(w[i - 15], 1) ^ _sha_right_rotate64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		sha384_word s1 = _sha_right_rotate64(w[i - 2], 19) ^ _sha_right_rotate64(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	sha384_word a = sh->hash[0];
	sha384_word b = sh->hash[1];
	sha384_word c = sh->hash[2];
	sha384_word d = sh->hash[3];
	sha384_word e = sh->hash[4];
	sha384_word f = sh->hash[5];
	sha384_word g = sh->hash[6];
	sha384_word h = sh->hash[7];

	for (int i = 0; i < 80; ++i)
	{
		sha384_word s0 = _sha_right_rotate64(a, 28) ^ _sha_right_rotate64(a, 34) ^ _sha_right_rotate64(a, 39);
		sha384_word maj = (a & b) ^ (a & c) ^ (b & c);
		sha384_word t2 = s0 + maj;
		sha384_word s1 = _sha_right_rotate64(e, 14) ^ _sha_right_rotate64(e, 18) ^ _sha_right_rotate64(e, 41);
		sha384_word ch = (e & f) ^ ((~e) & g);
		sha384_word t1 = h + s1 + ch + round_constants[i] + w[i];
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

static bool _sha384_512_checksum(void* buf, size_t size, struct sha384_hash* hash)
{
	char	*pbuf = (char*)buf;
	uint128_t	msg_bit_size = mult128(size, 8);
	size_t	size_tobe_readed = size;
	size_t	msg_size = STACK_BUFFER_SIZE;
	char	buffer[_sha384_file_chunk_size(STACK_BUFFER_SIZE)] = {0};

	if (hash->is_sha384_or_sha512)
	{
		init_sha384_hash(hash);
	}
	else
	{
		init_sha512_hash(hash);
	}
	
	while (size_tobe_readed > 0)
	{
		//slice the input buffer to 512B's msg
		size_t rd = size_tobe_readed > msg_size ? msg_size : size_tobe_readed;
		memcpy(buffer, pbuf, rd);
		size_tobe_readed -= rd;
		pbuf += rd;
		//is last msg?
		if (rd < msg_size)
		{
			// filling 1bit, 0s...
			buffer[rd] = 0x80;
			memset(&buffer[1 + rd], 0, _sha384_filling_size(rd) - 1);
			*((uint128_t*)(buffer + _sha384_filling_size(rd) + rd)) = 
				_sha384_msg_size_be(msg_bit_size);
			//corrected last msg size
			msg_size = rd + _sha384_padding_size(rd);
		}

		for (size_t s = 0; s < msg_size; s += CHUNK_SIZE)
		{
			process_chunk(hash, &buffer[s]);
		}
	}
	
	return true;
}

bool sha512_checksum(void* buf, size_t size, struct sha512_hash* hash)
{
	hash->is_sha384_or_sha512 = false;
	return _sha384_512_checksum(buf, size, hash);
}

bool sha384_checksum(void* buf, size_t size, struct sha384_hash* hash)
{
	hash->is_sha384_or_sha512 = true;
	return _sha384_512_checksum(buf, size, hash);
}

static bool _sha384_512_file_checksum(const char* filepath, struct sha384_hash* hash)
{
	FILE	*fp = NULL;
	size_t	rd = 0;
	uint128_t	msg_bit_size = {0};
	size_t	msg_size = STACK_BUFFER_SIZE;
	size_t	file_size = 0;
	char	buffer[_sha384_file_chunk_size(STACK_BUFFER_SIZE)] = { 0 };

	fp = fopen(filepath, "r");

	if (fp == NULL)
	{
		return false;
	}
	
	if (hash->is_sha384_or_sha512)
	{
		init_sha384_hash(hash);
	}
	else
	{
		init_sha512_hash(hash);
	}

	while (true)
	{
		rd = fread(buffer, 1, msg_size, fp);

		if (rd < 1)
		{
			break;
		}

		file_size += rd;

		if (rd < msg_size)
		{
			// filling 1bits, 0s...
			buffer[rd] = 0x80;
			memset(&buffer[1 + rd], 0, _sha384_filling_size(rd) - 1);
			msg_bit_size = mult128(file_size, 8);
			*((uint128_t*)(buffer + _sha384_filling_size(rd) + rd)) = 
				_sha384_msg_size_be(msg_bit_size);
			//corrected last msg size
			msg_size = rd + _sha384_padding_size(rd);
		}

		for (size_t s = 0; s < msg_size; s += CHUNK_SIZE)
		{
			process_chunk(hash, &buffer[s]);
		}
	}

	fclose(fp);
	return true;
}

bool sha512_file_checksum(const char* filepath, struct sha512_hash* hash)
{
	hash->is_sha384_or_sha512 = false;
	return _sha384_512_file_checksum(filepath, hash);
}

bool sha384_file_checksum(const char* filepath, struct sha384_hash* hash)
{
	hash->is_sha384_or_sha512 = true;
	return _sha384_512_file_checksum(filepath, hash);
}

static struct sha_format_t sha384_fmt[] = {
	//hex, fmt, mini size
	{"hex", "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", 97},
	{"HEX", "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X", 97},
	{"h:e:x", "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:", 144},
	{"H:E:X", "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:", 144},
	{"h-e-x", "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-", 144},
	{"H-E-X", "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X-%.2X-%.2X-", 144}
};

static const char* sha384_format_str(const char* fmt)
{
	for (size_t i = 0; i < sizeof(sha384_fmt) / sizeof(sha384_fmt[0]); ++ i)
	{
		if (strcmp(fmt, sha384_fmt[i].type) == 0)
		{
			return sha384_fmt[i].fmt_str;
		}
	}
	//default hex
	return sha384_fmt[0].fmt_str;
}

static bool sha384_check_str_buffer_size(const char* fmt, size_t s)
{
	for (size_t i = 0; i < sizeof(sha384_fmt) / sizeof(sha384_fmt[0]); ++ i)
	{
		if (strcmp(fmt, sha384_fmt[i].type) == 0)
		{
			return s >= sha384_fmt[i].size;
		}
	}

	return s >= sha384_fmt[0].size;
}

bool sha384_hash_to_str(struct sha384_hash* hash, char* str, size_t ssize, const char *fmt)
{
	int	wt = 0;

	if (!sha384_check_str_buffer_size(fmt, ssize))
	{
		return false;
	}

	const char* new_fmt = sha384_format_str(fmt);

	for (int i = 0; (i < 6) && (ssize - wt > 0); ++ i)
	{
		wt += snprintf(str + wt, ssize - wt, 
			new_fmt, 
			(int)((hash->hash[i] & 0xff00000000000000) >> 56),
			(int)((hash->hash[i] & 0x00ff000000000000) >> 48),
			(int)((hash->hash[i] & 0x0000ff0000000000) >> 40),
			(int)((hash->hash[i] & 0x000000ff00000000) >> 32),
			(int)((hash->hash[i] & 0x00000000ff000000) >> 24),
			(int)((hash->hash[i] & 0x0000000000ff0000) >> 16),
			(int)((hash->hash[i] & 0x000000000000ff00) >> 8),
			(int)(hash->hash[i] & 0x00000000000000ff)
		);
	}
	//erase last :
	if (str[wt - 1] == ':' || str[wt - 1] == '-')
	{
		str[wt - 1] = 0;
	}

	return true;
}

static struct sha_format_t sha512_fmt[] = {
	//hex, fmt, mini size
	{"hex", "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", 129},
	{"HEX", "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X", 129},
	{"h:e:x", "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:", 192},
	{"H:E:X", "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:", 192},
	{"h-e-x", "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-", 192},
	{"H-E-X", "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X-%.2X-%.2X-", 192}
};

static const char* sha512_format_str(const char* fmt)
{
	for (size_t i = 0; i < sizeof(sha512_fmt) / sizeof(sha512_fmt[0]); ++ i)
	{
		if (strcmp(fmt, sha512_fmt[i].type) == 0)
		{
			return sha512_fmt[i].fmt_str;
		}
	}
	//default hex
	return sha512_fmt[0].fmt_str;
}

static bool sha512_check_str_buffer_size(const char* fmt, size_t s)
{
	for (size_t i = 0; i < sizeof(sha512_fmt) / sizeof(sha512_fmt[0]); ++ i)
	{
		if (strcmp(fmt, sha512_fmt[i].type) == 0)
		{
			return s >= sha512_fmt[i].size;
		}
	}

	return s >= sha512_fmt[0].size;
}

bool sha512_hash_to_str(struct sha512_hash* hash, char* str, size_t ssize, const char *fmt)
{
	int	wt = 0;

	if (!sha512_check_str_buffer_size(fmt, ssize))
	{
		return false;
	}

	const char* new_fmt = sha512_format_str(fmt);

	for (int i = 0; (i < 8) && (ssize - wt > 0); ++ i)
	{
		wt += snprintf(str + wt, ssize - wt, 
			new_fmt, 
			(int)((hash->hash[i] & 0xff00000000000000) >> 56),
			(int)((hash->hash[i] & 0x00ff000000000000) >> 48),
			(int)((hash->hash[i] & 0x0000ff0000000000) >> 40),
			(int)((hash->hash[i] & 0x000000ff00000000) >> 32),
			(int)((hash->hash[i] & 0x00000000ff000000) >> 24),
			(int)((hash->hash[i] & 0x0000000000ff0000) >> 16),
			(int)((hash->hash[i] & 0x000000000000ff00) >> 8),
			(int)(hash->hash[i] & 0x00000000000000ff)
		);
	}
	//erase last :
	if (str[wt - 1] == ':' || str[wt - 1] == '-')
	{
		str[wt - 1] = 0;
	}

	return true;
}