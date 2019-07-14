#include "gtest.h"
#include "sha256.h"
#include "sha-byteorder.h"
#include "sha-ulti.h"

#if _MSC_VER
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

TEST(SHA256, bufferFT)
{
    struct sha256_hash  hash;
    char    str[128] = {0};

    sha256_checksum("abc", 3, &hash);
    sha256_hash_to_hexstr(&hash, str, 128, "hex");
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
	sha256_hash_to_hexstr(&hash, str, 128, "hex");
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

        for (size_t i = 0; i < 1024; ++ i)
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

	sha256_checksum(pbuf, rd, &hash);
	sha256_hash_to_hexstr(&hash, str, 128, "h:e:x");
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

        for (size_t i = 0; i < 1024; ++ i)
		{
            fprintf(fp, "%d", i);
        }

		fclose(fp);
	}

	sha256_file_checksum("hij.txt", &hash);
	sha256_hash_to_hexstr(&hash, str, 128, "HEX");
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
}