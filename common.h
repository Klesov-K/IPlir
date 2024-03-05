/*
 * common.h
 *
 *  Created on: Jan 28, 2020
 *      Author: V.A.Kiryukhin
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <vector>
#include <algorithm>

using std::cout;
using std::endl;
using std::cerr;

const size_t kBitInByte   = 8;
const uint8_t kByteMask    = 0xFF;
const uint8_t kMsbByteMask = 0x80;
const size_t kByteValues = 256;
const size_t kGostKeyByteSize = 32;

using GostKey = uint8_t[kGostKeyByteSize];

std::string to_hex(const uint8_t *block, const size_t bytesize = 16)
{
	std::stringstream out;
	for (size_t i = 0; i < bytesize; i++)
		out << std::setw(2) << std::setfill('0') << std::hex << int(block[i]);
	return out.str();
}

std::string to_hex(const std::vector<uint8_t> &text)
{
	return to_hex(text.data(), text.size());
}

std::string to_bytes_plain_c(const uint8_t *block, const size_t bytesize = 16)
{
	std::stringstream out;
	for (size_t i = 0; i < bytesize; i++)
	{
		out << "0x" << std::setw(2) << std::setfill('0') << std::hex << int(block[i]);
		if (i != bytesize - 1)
			out << ", ";
	}
	return out.str();
}

std::string to_bytes_plain_c(const std::vector<uint8_t> &text)
{
	return to_bytes_plain_c(text.data(), text.size());
}


#endif /* COMMON_H_ */
