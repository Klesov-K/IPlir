/*
 * magma.h
 *
 *  Created on: Jan 27, 2020
 *      Author: V.A.Kiryukhin
 *
 */

#ifndef MAGMA_H_
#define MAGMA_H_

#include "common.h"
#include "block_functions.h"
#include "cipher_base.h"

class Magma: public BlockCipher
{
	public:
		static const size_t kSboxCount = 8;
		static const size_t kSboxValues = 16;
		static const size_t kRoundCount = 32;
		static const size_t kWordInKey = 8;
		static const size_t kBytesInWord = 4;
		static const size_t kBlockByteSize = 8;

		static uint32_t uint8ToUint32(const uint8_t *input)
		{
			return uint32_t((input[3]) | (input[2] << 8) | (input[1] << 16) | (input[0] << 24));
		}

		static void uint32ToUint8(uint32_t input, uint8_t *output)
		{
			for (size_t i = 0; i < sizeof(input); ++i)
			{
				output[sizeof(uint32_t) - i - 1] = ((input >> (kBitInByte * i)) & kByteMask);
			}
		}
	protected:
		//GOST R 34.12-2018
		uint8_t sbox_[kSboxCount][kSboxValues] =
		{
				{ 0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1 },
				{ 0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf },
				{ 0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0 },
				{ 0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb },
				{ 0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc },
				{ 0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0 },
				{ 0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7 },
				{ 0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2 }
		};

		const size_t kEncKeyIndex[kRoundCount] = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0 };

		const size_t kDecKeyIndex[kRoundCount] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0 };

		uint32_t round_keys_[8];

		uint32_t funcT(uint32_t a) const
		{
			uint32_t res = 0;

			res ^= sbox_[0][a & 0x0000000f];
			res ^= (sbox_[1][((a & 0x000000f0) >> 4)] << 4);
			res ^= (sbox_[2][((a & 0x00000f00) >> 8)] << 8);
			res ^= (sbox_[3][((a & 0x0000f000) >> 12)] << 12);
			res ^= (sbox_[4][((a & 0x000f0000) >> 16)] << 16);
			res ^= (sbox_[5][((a & 0x00f00000) >> 20)] << 20);
			res ^= (sbox_[6][((a & 0x0f000000) >> 24)] << 24);
			res ^= (sbox_[7][((a & 0xf0000000) >> 28)] << 28);

			return res;
		}

		uint32_t funcG(uint32_t a, uint32_t k) const
		{
			uint32_t c = a + k;

			uint32_t tmp = funcT(c);

			uint32_t r = (tmp << 11) | (tmp >> 21);

			return r;
		}

		void round(uint32_t *a1, uint32_t *a0, uint32_t k) const
		{
			uint32_t a = *a0;
			uint32_t tmp = funcG(*a0, k);

			*a0 = *a1 ^ tmp;
			*a1 = a;
		}

		void roundFinal(uint32_t *a1, uint32_t *a0, uint32_t k) const
		{
			uint32_t tmp = funcG(*a0, k);
			*a1 ^= tmp;
		}

		void rounds(uint32_t &a1, uint32_t &a0, const size_t *key_index, const uint32_t *round_keys) const
		{
			for (size_t i = 0; i < kRoundCount - 1; ++i)
			{
				//cout << std::hex << a0 << " " << a1 << endl;
				round(&a1, &a0, round_keys[key_index[i]]);
			}
			//cout << std::hex << std::setfill('0') << std::setw(8) << a0 << " " << std::setw(8) << a1 << endl;
			roundFinal(&a1, &a0, round_keys[key_index[kRoundCount - 1]]);
			//cout << std::hex << std::setfill('0') << std::setw(8) << a0 << " " << std::setw(8) << a1 << endl;
		}

		virtual void cryptBlock(const uint8_t *input, uint8_t *output, const uint32_t *round_keys, const size_t *key_index) const
		{
			uint32_t a1 = uint8ToUint32(input);
			uint32_t a0 = uint8ToUint32(input + kBytesInWord);

			rounds(a1, a0, key_index, round_keys);

			uint32ToUint8(a1, output);
			uint32ToUint8(a0, output + kBytesInWord);
		}

		virtual void keySchedule(const uint8_t *key, uint32_t *round_keys) const
		{
			for (size_t i = 0; i < kWordInKey; i++)
				round_keys[i] = uint8ToUint32(key + i * kBytesInWord);
		}

	public:

		Magma(){}

		Magma(const uint8_t *key)
		{
			initKey(key);
		}

		virtual void initKey(const uint8_t *key)
		{
			keySchedule(key, round_keys_);
		}

		virtual void encrypt(const uint8_t *plain_block, uint8_t *cipher_block) const
		{
			cryptBlock(plain_block, cipher_block, round_keys_, kEncKeyIndex);
		}

		virtual void decrypt(const uint8_t *cipher_block, uint8_t *plain_block) const
		{
			cryptBlock(cipher_block, plain_block, round_keys_, kDecKeyIndex);
		}

		virtual void encrypt(const uint8_t *key, const uint8_t *plain_block , uint8_t *cipher_block) const
		{
			uint32_t round_keys[kWordInKey];
			keySchedule(key, round_keys);
			cryptBlock(plain_block, cipher_block, round_keys, kEncKeyIndex);
		}

		virtual void decrypt(const uint8_t *key, const uint8_t *cipher_block, uint8_t *plain_block) const
		{
			uint32_t round_keys[kWordInKey];
			keySchedule(key, round_keys);
			cryptBlock(cipher_block, plain_block, round_keys_, kDecKeyIndex);
		}


		virtual size_t getBlockByteSize() const
		{
			return kBlockByteSize;
		}
};

class GOST89: public Magma
{
		virtual void keySchedule(const uint8_t *key, uint32_t *round_keys) const
		{
			for (size_t i = 0; i < kWordInKey; i++)
				round_keys[i] = GOST89::uint8ToUint32(key + i * kBytesInWord);
		}

	public:

		static uint32_t uint8ToUint32(const uint8_t *input)
		{
			return uint32_t((input[0]) | (input[1] << 8) | (input[2] << 16) | (input[3] << 24));
		}

		static void uint32ToUint8(uint32_t input, uint8_t *output)
		{
			for (size_t i = 0; i < sizeof(input); ++i)
			{
				output[i] = ((input >> (kBitInByte * i)) & kByteMask);
			}
		}


		virtual void cryptBlock(const uint8_t *input, uint8_t *output, const uint32_t *round_keys, const size_t *key_index) const
		{
			uint32_t a1 = GOST89::uint8ToUint32(input + kBytesInWord);
			uint32_t a0 = GOST89::uint8ToUint32(input);

			rounds(a1, a0, key_index, round_keys);

			GOST89::uint32ToUint8(a1, output + kBytesInWord);
			GOST89::uint32ToUint8(a0, output);
		}

		void initSbox(const uint8_t sbox[kSboxCount][kSboxValues])
		{
			for (size_t i = 0; i < kSboxCount; i++)
			{
				for (size_t j = 0; j < kSboxValues; j++)
				{
					sbox_[i][j] = sbox[i][j];
				}
			}
		}

		virtual void initKey(const uint8_t *key)
		{
			keySchedule(key, round_keys_);
		}

		GOST89(){}

		GOST89(const uint8_t *key)
		{
			initKey(key);
		}

		GOST89(const uint8_t *key, const uint8_t sbox[kSboxCount][kSboxValues])
		{
			initKey(key);
			initSbox(sbox);
		}


		virtual void imitCryptBlock(const uint8_t *input, uint8_t *output) const
		{
			const size_t kImitRoundCount = 16;
			uint32_t a1 = GOST89::uint8ToUint32(input + kBytesInWord);
			uint32_t a0 = GOST89::uint8ToUint32(input);

			for (size_t i = 0; i < kImitRoundCount; ++i)
			{
				round(&a1, &a0, round_keys_[kEncKeyIndex[i]]);
			}
			//roundFinal(&a1, &a0, round_keys_[kEncKeyIndex[kImitRoundCount - 1]]);

			GOST89::uint32ToUint8(a1, output + kBytesInWord);
			GOST89::uint32ToUint8(a0, output);
		}

		void imit(const uint8_t *text, const size_t text_bytesize, uint8_t *mac) const
		{
			const size_t kMacByteSize = 4;
			const size_t kMinBlockCount = 2;
			if (text_bytesize % kBlockByteSize != 0)
			{
				cerr << "Unpadded block!" << endl;
				return;
			}

			const size_t block_count = text_bytesize / kBlockByteSize;
			if (block_count < kMinBlockCount)
			{
				cerr << "block_count < 2" << endl;
				return;
			}

			uint8_t temp[kBlockByteSize] = {0x00};

			for (size_t i = 0; i < text_bytesize; i += kBlockByteSize)
			{
				xorBlock(temp, temp, text + i, kBlockByteSize);
				imitCryptBlock(temp, temp);
			}


			memcpy(mac, temp, kMacByteSize);
		}

};

using MagmaPtr = std::shared_ptr<Magma>;
using GOST89Ptr = std::shared_ptr<GOST89>;


BlockCipherPtr buildTestMagma()
{
	GostKey key = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	return buildBlockCipher<Magma>(key);
}

GOST89Ptr buildTestGOST89()
{
	uint8_t p[8][16] =
	{
	{0x4,0x2,0xF,0x5,0x9,0x1,0x0,0x8,0xE,0x3,0xB,0xC,0xD,0x7,0xA,0x6},
	{0xC,0x9,0xF,0xE,0x8,0x1,0x3,0xA,0x2,0x7,0x4,0xD,0x6,0x0,0xB,0x5},
	{0xD,0x8,0xE,0xC,0x7,0x3,0x9,0xA,0x1,0x5,0x2,0x4,0x6,0xF,0x0,0xB},
	{0xE,0x9,0xB,0x2,0x5,0xF,0x7,0x1,0x0,0xD,0xC,0x6,0xA,0x4,0x3,0x8},
	{0x3,0xE,0x5,0x9,0x6,0x8,0x0,0xD,0xA,0xB,0x7,0xC,0x2,0x1,0xF,0x4},
	{0x8,0xF,0x6,0xB,0x1,0x9,0xC,0x5,0xD,0x3,0x7,0xA,0x0,0xE,0x2,0x4},
	{0x9,0xB,0xC,0x0,0x3,0x6,0x7,0x5,0x4,0x8,0xE,0xF,0x1,0xA,0x2,0xD},
	{0xC,0x6,0x5,0x2,0xB,0x0,0x9,0xD,0x3,0xE,0x7,0xA,0xF,0x4,0x1,0x8}
	};

	GostKey key = {0x04,0x75,0xF6,0xE0,0x50,0x38,0xFB,0xFA,0xD2,0xC7,0xC3,0x90,0xED,0xB3,0xCA,0x3D,0x15,0x47,0x12,0x42,0x91,0xAE,0x1E,0x8A,0x2F,0x79,0xCD,0x9E,0xD2,0xBC,0xEF,0xBD};

	return std::make_shared<GOST89>(key, p);
}

#endif /* MAGMA_H_ */
