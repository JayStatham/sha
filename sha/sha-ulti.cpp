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
#include "sha-ulti.h"

void print_memory_buffer(void* address, size_t wide, size_t size)
{
	memory_block	mb(address, wide, size);
	std::cout << mb;
}

// override << for sha256_hash
std::ostream& operator << (std::ostream& out, struct sha256_hash & hash)
{
	char    buf[128] = { 0 };
	bool flag = (out.flags() & std::ios::uppercase) > 0;
	sha256_hash_to_hexstr(&hash, buf, 128, flag);
	out << buf;
	return out;
}
// override << for sha256_hash*
std::ostream& operator << (std::ostream& out, struct sha256_hash * hash)
{
	out << *hash;
	return out;
}

std::ostream& operator << (std::ostream& out, struct memory_block & mb)
{
	auto f = out.flags();

	try
	{
		int pn = 60 - sizeof(long) * 2 - 3;
		//content-hex
		size_t count = pn / (mb.wide * 3 + 1);
		//print header info
		out << "memory address:0x" << std::nouppercase
			<< mb.address << ", wide:" << mb.wide
			<< ", size:" << mb.size << std::endl;
		//print title:
		out << std::left << std::setw(sizeof(long) * 2 + 3) << "address"
			<< std::setw((count*2 + 1) * mb.wide) << "content"
			<< std::left << std::setw(count * mb.wide) << "string" << std::endl;
		out << "__________________________________________________" << std::endl;
		//print contents
		char*	p = (char*)mb.address;
		size_t	addr_wide = sizeof(long) * 2 + 2;

		for (size_t n = 0; n < mb.size;)
		{
			//address
			std::streampos sp = out.tellp();
			out << "0x" << std::hex << std::setw(sizeof(long) * 2)
				<< std::setprecision(sizeof(long)) << std::setfill('0')
				<< std::nouppercase
				<< (unsigned long*)(&p[n]) << " ";

			for (size_t i = 0, nn = n; i < count; ++i)
			{
				for (size_t k = 0; k < mb.wide; ++k, ++nn)
				{
					if (nn < mb.size)
					{
						out << std::hex << std::setw(2) << std::setfill('0')
							<< std::setprecision(2) << (int)(p[nn] & 0xff);
					}
					else
					{
						out << "  ";
					}
				}

				out << " ";
			}
			//content-string
			for (size_t i = 0; i < count * mb.wide; ++i, ++n)
			{
				if (n < mb.size)
				{
					int	a = p[n] & 0xff;

					if (isprint(a))
					{
						out.put(a);
					}
					else
					{
						out << ".";
					}
				}
				else
				{
					out << " ";
				}
			}

			out << std::endl;
		}
		//over
		out << "____________________________________________________" << std::endl;
		out.setf(f);
		out << std::setfill(' ');
		return out;
	}
	catch (std::exception &e)
	{
		out.setf(f);
		out << std::setfill(' ');
		throw e;
	}
}
