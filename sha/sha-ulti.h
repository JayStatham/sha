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

#ifdef __cplusplus
#include <iostream>
#include <iomanip>
#include "sha.h"
// memory/address block
struct memory_block
{
    void*   address{nullptr};
    size_t  wide{4};        //uint32_t wide
    size_t  size{0};        //size in bytes
    memory_block(void* addr, size_t w, size_t s) : address(addr), wide(w), size(s){}
};
// override << for sha256_hash
std::ostream& operator << (std::ostream& out, struct sha256_hash & hash);
// override << for sha256_hash*
std::ostream& operator << (std::ostream& out, struct sha256_hash * hash);
// override << for sha384_hash
std::ostream& operator << (std::ostream& out, struct sha384_hash & hash);
// override << for sha384_hash*
std::ostream& operator << (std::ostream& out, struct sha384_hash * hash);
std::ostream& operator << (std::ostream& out, struct memory_block & mb);
#endif

#ifdef __cplusplus
extern "C" {
#endif
    struct sha_format_t
    {
        const char* type;
        const char* fmt_str;
        size_t		size;
    };
	void print_memory_buffer(void* address, size_t wide, size_t size);
#ifdef __cplusplus
}
#endif