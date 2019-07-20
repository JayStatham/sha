/***********************************************************************************
The MIT License (MIT)
Copyright (c) 2018 JStatham
Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sub license, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, subject 
to the following conditions:
The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,FITNESS FOR A PARTICULAR 
PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE.
**************************************************************************************/
#include "gtest.h"
#include "sha256.h"
#include "sha-byteorder.h"
#include "sha-ulti.h"

#if _MSC_VER
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

TEST(SHA256, buffer)
{
    struct sha256_hash  hash;
    char    str[128] = {0};

    sha256_checksum((void*)"abc", 3, &hash);
    sha256_hash_to_str(&hash, str, 128, "hex");
    ASSERT_STREQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", str);
	std::cout << hash << std::endl;
}

TEST(SHA256, file)
{
	struct sha256_hash  hash;
	char    str[128] = { 0 };
	//create file
	{
		FILE *fp = fopen("abc.txt", "w");
		fwrite("abc", 1, 3, fp);
		fclose(fp);
	}

	sha256_file_checksum("abc.txt", &hash);
	sha256_hash_to_str(&hash, str, 128, "hex");
	ASSERT_STREQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", str);
	std::cout << hash << std::endl;
}

TEST(SHA256, big_buffer)
{
	struct sha256_hash  hash;
	char    str[128] = { 0 };
	//create file
	{
		FILE *fp = fopen("efg.txt", "w");

        for (int i = 0; i < 1024; ++ i)
		{
            fprintf(fp, "%d", i);
        }

		fclose(fp);
	}

    char* pbuf = (char*)malloc(4096);
    ASSERT_TRUE(pbuf != nullptr);
    size_t  rd = 0;
    //read file to buffer
    {
        FILE *fp = fopen("efg.txt", "r");
        rd = fread(pbuf, 1, 4096, fp);
        ASSERT_TRUE(rd > 0);
		fclose(fp);
    }

	sha256_checksum((void*)pbuf, rd, &hash);
	sha256_hash_to_str(&hash, str, 128, "h:e:x");
	ASSERT_STREQ("5c:d4:f6:7c:99:09:e8:71:8f:24:a3:ba:a5:2e:5b:3c:ee:88:f2:9b:a4:aa:85:ac:94:aa:7c:88:39:64:69:5d", str);
	std::cout << hash << std::endl;
    free(pbuf);
}

TEST(SHA256, file2)
{
	struct sha256_hash  hash;
	char    str[128] = { 0 };
	//create file
	{
		FILE *fp = fopen("hij.txt", "w");

        for (int i = 0; i < 1024; ++ i)
		{
            fprintf(fp, "%d", i);
        }

		fclose(fp);
	}

	sha256_file_checksum("hij.txt", &hash);
	sha256_hash_to_str(&hash, str, 128, "HEX");
	ASSERT_STREQ("5CD4F67C9909E8718F24A3BAA52E5B3CEE88F29BA4AA85AC94AA7C883964695D", str);
	std::cout << hash << std::endl;
}

TEST(BYTEORDER, base)
{
    int a = htonl(1);
    ASSERT_EQ(a, _sha_be32(1));
    short b = htons(1);
    ASSERT_EQ(b, _sha_be16(1));
    ASSERT_EQ(0x0100000000000000, _sha_be64(1));
    int a1 = htonl(0x303030a5);
    ASSERT_EQ(a1, _sha_be32(0x303030a5));
    uint16_t b1 = htons(0x55aa);
    ASSERT_EQ(b1, _sha_be16(0x55aa));
    ASSERT_EQ(0x1122334455667788, _sha_be64(0x8877665544332211));
}

TEST(BIT, rotate)
{
    ASSERT_EQ(0x80000000, _sha_right_rotate32(1, 1));
    ASSERT_EQ(1, _sha_right_rotate32(0x80000000, 31));
    ASSERT_EQ(0xa0000000, _sha_right_rotate32(5, 3));
    ASSERT_EQ(0x2, _sha_left_rotate32(1, 1));
    ASSERT_EQ(0x80000000, _sha_left_rotate32(1, 31));
    ASSERT_EQ(0x28, _sha_left_rotate32(5, 3));
	ASSERT_EQ(0x0010, _sha_left_rotate64(1, 4));
	ASSERT_EQ(0x0010, _sha_right_rotate64(0x100, 4));
}

TEST(SHA384, buffer)
{
    struct sha384_hash  hash;
    char    str[128] = {0};

    sha384_checksum((void*)"abc", 3, &hash);
    sha384_hash_to_str(&hash, str, 128, "hex");
    ASSERT_STREQ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", str);
	std::cout << hash << std::endl;
}

TEST(SHA512, buffer)
{
    struct sha512_hash  hash;
    char    str[256] = {0};

    sha512_checksum((void*)"abc", 3, &hash);
    sha512_hash_to_str(&hash, str, 256, "hex");
    ASSERT_STREQ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", str);
	std::cout << hash << std::endl;
}

TEST(SHA384, file)
{
	struct sha384_hash  hash;
	char    str[256] = { 0 };
	//create file
	{
		FILE *fp = fopen("384.txt", "w");

        for (int i = 0; i < 1024; ++ i)
		{
            fprintf(fp, "%d", i);
        }

		fclose(fp);
	}

	sha384_file_checksum("384.txt", &hash);
	sha384_hash_to_str(&hash, str, 256, "HEX");
	ASSERT_STREQ("01D9A057D03597D261EB3C31C300A5E07A66B2702EEBE2018F92C4B44858D9F360E87430F3DB884CB9DB37F9154D9AF4", str);
	std::cout << hash << std::endl;
}

TEST(SHA512, file)
{
	struct sha512_hash  hash;
	char    str[256] = { 0 };
	//create file
	{
		FILE *fp = fopen("512.txt", "w");

        for (int i = 0; i < 1024; ++ i)
		{
            fprintf(fp, "%d", i);
        }

		fclose(fp);
	}

	sha512_file_checksum("512.txt", &hash);
	sha512_hash_to_str(&hash, str, 256, "h:e:x");
	ASSERT_STREQ("93:f2:77:4a:79:29:f2:cd:fd:e6:79:c2:e1:21:e9:2b:29:9c:32:1c:3d:a4:f2:c9:b2:25:37:80:8d:58:ba:84:06:55:dd:4c:94:c9:bb:8b:ca:da:d6:ad:c1:ed:5c:d6:46:a2:e2:65:e3:dc:3f:28:44:4a:4d:7e:a5:78:7d:a8", str);
	std::cout << hash << std::endl;
}

#if 0
TEST(SHA512, file2)
{
	struct sha512_hash  hash;
	char    str[256] = { 0 };

	sha512_file_checksum("b512.pdb", &hash);
	sha512_hash_to_str(&hash, str, 256, "HEX");
	ASSERT_STREQ("B4FDB25899B004F7586A498BFCE2F7138F21DEBBED27BAC52CFAB1827BBE5104D8A6BE59BBDDCD3B2C04F9D3FCC1A870614D55A515D88CAEF4D53B617F4A65A7", str);
	std::cout << memory_block(&str[0], 1, sizeof(str));
	std::cout << hash << std::endl;
}
#endif

TEST(UINT128, left_shift)
{
	uint128_t	z = {0};
	
#if _SHA_BYTE_ODER_LE
	//small numbers
	z = bit_shift_left64(1, 8);
	ASSERT_EQ(z.u64[0], 256);
	//edge
	z = bit_shift_left64(0x8000000000000001, 1);
	ASSERT_EQ(z.u64[0], 2);
	ASSERT_EQ(z.u64[1], 1);
#else 
	//small numbers
	z = bit_shift_left64(1, 8);
	ASSERT_EQ(z.u64[1], 256);
	//edge
	z = bit_shift_left64(0x8000000000000001, 1);
	ASSERT_EQ(z.u64[1], 2);
	ASSERT_EQ(z.u64[0], 1);
#endif
}