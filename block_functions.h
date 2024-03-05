/*
 * block_functions.h
 *
 *  Created on: Jan 30, 2020
 *      Author: V.A.Kiryukhin
 */

#ifndef BLOCK_FUNCTIONS_H_
#define BLOCK_FUNCTIONS_H_

#include "common.h"

void xorBlock(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, const size_t bytesize)
{
	for (size_t i = 0; i < bytesize; i++)
		dst[i] = src1[i] ^ src2[i];
}

void blockPlusOne(uint8_t *block, const size_t bytesize)
{
	int pos = bytesize;
	do
	{
		pos--;
		block[pos]++;
	}
	while(block[pos] == 0x00 && pos > 0);
}

void ctrIncrementLeft(uint8_t *block, const size_t bytesize)
{
	blockPlusOne(block, bytesize/2);
}

void ctrIncrementRight(uint8_t *block, const size_t bytesize)
{
	blockPlusOne(block + bytesize/2, bytesize/2);
}

uint8_t getPrimitivePolynomialCoef(const size_t degree)
{
	if (degree == 64)
		return 0x1B;
	if (degree == 128)
		return 0x87;

	std::cerr << "Non-valid block size!" << std::endl;
	return 0x00;
}

void blockLeftShift(uint8_t *block, const size_t bytesize)
{
	for (size_t i = 0; i < bytesize - 1; i++)
	{
		block[i] <<= 1;
		block[i] &= 0xFE;
		block[i] |= ((block[i + 1] >> 7) & 0x01);
	}
	block[bytesize - 1] <<= 1;
	block[bytesize - 1] &= 0xFE;
}

void blockRightShift(uint8_t *block, const size_t bytesize)
{
	int lowestBit, highestBit;
	for (size_t i = 0; i < bytesize; i++)
	{
		lowestBit = block[i] & 0x01;
		block[i] >>= 1;
		if(i != 0)
		{
			block[i] |= (highestBit==0)?(0):(0x80);
		}
		highestBit = lowestBit;
	}
}

bool msbBlock(uint8_t *block)
{
	return (block[0] & 0x80);
}

size_t bytesizeToBlocksize(const size_t bytesize, const size_t block_bytesize)
{
	size_t blocksize = bytesize / block_bytesize;
	if (bytesize % block_bytesize != 0)
		blocksize++;
	return blocksize;
}

size_t getLastBlockBytesize(const size_t bytesize, const size_t block_bytesize)
{
	size_t last_block_bytesize = bytesize % block_bytesize;
	if (last_block_bytesize == 0)
		last_block_bytesize = block_bytesize; //full block
	return last_block_bytesize;
}

bool getBit(const uint8_t *block, const size_t bitpos)
{
	const size_t bytepos = bitpos / kBitInByte;
	const size_t bitpos_in_byte = (kBitInByte-1) - (bitpos % kBitInByte);
	return block[bytepos] & (1 << bitpos_in_byte);
}

template<typename Uint>
void uintToBlock(Uint uint_val, uint8_t *block, const size_t block_bytesize)
{
	memset(block, 0, block_bytesize);
	for (size_t i = 0; i < block_bytesize; i++)
	{
		block[block_bytesize - 1 - i] = uint_val & kByteMask;
		uint_val >>= kBitInByte;
	}
}

void fieldMultiplication(uint8_t *result, const uint8_t *block1, const uint8_t *block2, const size_t block_bytesize)
{
	const uint8_t polynomCoef = getPrimitivePolynomialCoef(block_bytesize * kBitInByte);

	//uint8_t temp[block_bytesize];
	//uint8_t temp_sum[block_bytesize] = {0x00};

	std::vector<uint8_t> v_temp(block_bytesize);
	uint8_t* temp = v_temp.data();

	std::vector<uint8_t> v_temp_sum(block_bytesize);
	uint8_t* temp_sum = v_temp_sum.data();

	memcpy(temp, block2, block_bytesize);

	for (int i = block_bytesize * kBitInByte - 1; i >= 0; i--)
	{
		if (getBit(block1, i))
			xorBlock(temp_sum, temp_sum, temp, block_bytesize);

		if (msbBlock(temp))
		{
			blockLeftShift(temp, block_bytesize);
			temp[block_bytesize - 1] ^= polynomCoef;
		}
		else
		{
			blockLeftShift(temp, block_bytesize);
		}
	}

	memcpy(result, temp_sum, block_bytesize);
}

void fieldMultiplicationGCM(uint8_t *result, const uint8_t *block1, const uint8_t *block2)
{
	const size_t kBlockByteSize = 16;

	uint8_t temp[kBlockByteSize];
	uint8_t temp_sum[kBlockByteSize] = {0x00};

	memcpy(temp, block2, kBlockByteSize);


	for (size_t i = 0; i < kBlockByteSize; i++)
	{

		for (size_t j = 0; j < kBitInByte; j++)
		{
			int x_bit = block1[i] >> (7-j) &1;

			if (x_bit & 0x01)
			{
				xorBlock(temp_sum, temp_sum, temp, kBlockByteSize);
			}

			if (temp[kBlockByteSize-1] & 0x01)
			{
				blockRightShift(temp, kBlockByteSize);
				temp[0] ^= 0xe1; //1+x+x^2+x^7
			}
			else
			{
				blockRightShift(temp, kBlockByteSize);
			}
		}
	}

	memcpy(result, temp_sum, kBlockByteSize);
}



void setZeroMsb(uint8_t *block)
{
	block[0] &= 0b01111111;
}

void setOneMsb(uint8_t *block)
{
	block[0] |= 0b10000000;
}

#endif /* BLOCK_FUNCTIONS_H_ */
