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

    sha256_checksum("abc", 3, &hash);
    sha256_hash_to_hexstr(&hash, str, 128, false);
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
	sha256_hash_to_hexstr(&hash, str, 128, false);
	ASSERT_STREQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", str);
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