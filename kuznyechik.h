/*
 * kuznyechik.h
 *
 *  Created on: Jan 27, 2020
 *      Author: V.A.Kiryukhin
 */

#ifndef KUZNYECHIK_H_
#define KUZNYECHIK_H_

class Kuznyechik: public BlockCipher
{
		static const size_t kFullIterationsCount = 9;

		static const size_t kKeyBitSize = 256;
		static const size_t kKeyByteSize = 32;
		static const size_t kBlockBitSize = 128;
		static const size_t kBlockByteSize = 16;

		static const size_t kFieldSize = 256;

	public:
		static const uint8_t sbox_[kByteValues]; //S
		static const uint8_t sbox_inv_[kByteValues]; //S^(-1)
		static const uint8_t linear_const_[kBlockByteSize];
		static const uint8_t mult_table_[kFieldSize * kFieldSize]; // * in GF(2^8)

		uint8_t round_keys_[kFullIterationsCount + 1][kBlockByteSize];

		void sTransform(uint8_t *block) const
		{
			for (size_t i = 0; i < kBlockByteSize; i++)
				block[i] = sbox_[block[i]];
		}

		void rTransform(uint8_t *block) const
		{
			uint8_t l = linearRegisterOutput(block);
			for (size_t i = kBlockByteSize - 1; i > 0; i--)
				block[i] = block[i - 1];
			block[0] = l;
		}

		void lTransform(uint8_t *block) const
		{
			for (size_t i = 0; i < kBlockByteSize; i++)
				rTransform(block);
		}

		uint8_t linearRegisterOutput(uint8_t *block) const
		{
			uint8_t l = 0;
			for (size_t i = 0; i < kBlockByteSize; i++)
				l ^= mult_table_[block[i] * kFieldSize + linear_const_[i]];
			return l;
		}

		void sInvTransform(uint8_t *block) const
		{
			for (size_t i = 0; i < kBlockByteSize; i++)
				block[i] = sbox_inv_[block[i]];
		}

		void rInvTransform(uint8_t *block) const
		{
			uint8_t l = block[0];
			for (size_t i = 0; i < kBlockByteSize - 1; i++)
				block[i] = block[i + 1];
			block[kBlockByteSize - 1] = l;

			block[kBlockByteSize - 1] = linearRegisterOutput(block);
		}

		void lInvTransform(uint8_t *block) const
		{
			for (size_t i = 0; i < kBlockByteSize; i++)
				rInvTransform(block);
		}

		void encryptBlock(uint8_t *block, const uint8_t round_keys[kFullIterationsCount + 1][kBlockByteSize]) const
		{
			for (size_t i = 0; i < kFullIterationsCount; i++)
			{
				//X
				for (size_t j = 0; j < kBlockByteSize; j++)
					block[j] ^= round_keys[i][j];
				//S
				sTransform(block);
				//L
				lTransform(block);
			}

			//10'th truncated round
			for (size_t j = 0; j < kBlockByteSize; j++)
				block[j] ^= round_keys[kFullIterationsCount][j];

		}


		void decryptBlock(uint8_t *block, const uint8_t round_keys[kFullIterationsCount + 1][kBlockByteSize]) const
		{
			//10'th inverse round
			for (size_t j = 0; j < kBlockByteSize; j++)
				block[j] ^= round_keys[kFullIterationsCount][j];

			for (int i = kFullIterationsCount - 1; i >= 0; i--)
			{
				//L
				lInvTransform(block);
				//S
				sInvTransform(block);
				//X
				for (size_t j = 0; j < kBlockByteSize; j++)
					block[j] ^= round_keys[i][j];
			}

		}

		void getIterationConst(uint8_t *C_i, const size_t i) const
		{
			memset(C_i, 0, kBlockByteSize);
			C_i[kBlockByteSize - 1] = i;
			lTransform(C_i);
		}

		void keySchedule(const uint8_t *key, uint8_t round_keys[kFullIterationsCount + 1][kBlockByteSize]) const
		{
			const size_t kKeyScheduleRounds = 8;
			const size_t kKeyScheduleSteps = (kFullIterationsCount + 1 - 2) / 2;

			for (size_t i = 0; i < kBlockByteSize; i++)
				round_keys[0][i] = key[i]; //K_0
			for (size_t i = 0; i < kBlockByteSize; i++)
				round_keys[1][i] = key[i + kBlockByteSize]; //K_1

			uint8_t block1[kBlockByteSize];
			uint8_t block2[kBlockByteSize];

			memcpy(block1, round_keys[0], kBlockByteSize);
			memcpy(block2, round_keys[1], kBlockByteSize);

			for (size_t i = 1; i <= kKeyScheduleSteps; i++)
			{
				for (size_t j = 1; j <= kKeyScheduleRounds; j++)
				{
					uint8_t LSX_result[kBlockByteSize];

					uint8_t C[kBlockByteSize];
					getIterationConst(C, kKeyScheduleRounds * (i - 1) + j);

					//X_transform
					for (size_t i = 0; i < kBlockByteSize; i++)
						LSX_result[i] = C[i] ^ block1[i];
					sTransform(LSX_result);
					lTransform(LSX_result);

					for (size_t i = 0; i < kBlockByteSize; i++)
						LSX_result[i] ^= block2[i];

					memcpy(block2, block1, kBlockByteSize);
					memcpy(block1, LSX_result, kBlockByteSize);

				}
				memcpy(round_keys[2 * i], block1, kBlockByteSize);
				memcpy(round_keys[2 * i + 1], block2, kBlockByteSize);
			}
		}

	public:

		Kuznyechik(){}

		Kuznyechik(const uint8_t *key)
		{
			initKey(key);
		}

		virtual void initKey(const uint8_t *key)
		{
			keySchedule(key, round_keys_);
		}

		virtual void encrypt(const uint8_t *plain_block, uint8_t *cipher_block) const
		{
			memcpy(cipher_block, plain_block, kBlockByteSize);
			encryptBlock(cipher_block, round_keys_);
		}

		virtual void decrypt(const uint8_t *cipher_block, uint8_t *plain_block) const
		{
			memcpy(plain_block, cipher_block, kBlockByteSize);
			decryptBlock(plain_block, round_keys_);
		}

		virtual void encrypt(const uint8_t *key, const uint8_t *plain_block , uint8_t *cipher_block) const
		{
			uint8_t round_keys[kFullIterationsCount + 1][kBlockByteSize];
			keySchedule(key, round_keys);
			memcpy(cipher_block, plain_block, kBlockByteSize);
			encryptBlock(cipher_block, round_keys);
		}

		virtual void decrypt(const uint8_t *key, const uint8_t *cipher_block, uint8_t *plain_block) const
		{
			uint8_t round_keys[kFullIterationsCount + 1][kBlockByteSize];
			keySchedule(key, round_keys);
			memcpy(plain_block, cipher_block, kBlockByteSize);
			decryptBlock(plain_block, round_keys);
		}

		virtual size_t getBlockByteSize() const
		{
			return kBlockByteSize;
		}
};

#include "kuznyechik_tables.h"

BlockCipherPtr buildTestKuznyechik()
{
	GostKey key = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98,
						0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	return buildBlockCipher<Kuznyechik>(key);
}


#endif /* KUZNYECHIK_H_ */
