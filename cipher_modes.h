

#ifndef CIPHER_MODES_H_
#define CIPHER_MODES_H_

#include "message.h"
#include "block_functions.h"
#include "cipher_base.h"

//GOST R 34.13-2018 pp.4.1.1
void paddingZeros(const vector<uint8_t> &text, vector<uint8_t> &padded_text, const size_t block_size)
{
	size_t text_size = text.size();
	size_t padded_text_size = text.size();
	if (padded_text_size % block_size != 0)
		padded_text_size += block_size - (padded_text_size % block_size);
	padded_text.resize(padded_text_size, 0x00);
	memcpy(padded_text.data(), text.data(), text.size());
	memset(padded_text.data() + text_size, 0x00, padded_text_size - text_size);
}

class ECB
{
	public:
		static void encrypt(const BlockCipherPtr cipher_ptr, const uint8_t *plaintext, uint8_t *ciphertext, const size_t data_bytesize)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (data_bytesize % block_bytesize != 0)
			{
				cerr << "Unpadded text!" << endl;
				return;
			}

			for (size_t i = 0; i < data_bytesize; i += block_bytesize)
			{
				cipher_ptr->encrypt(plaintext + i, ciphertext + i);
			}
		}

		static void encrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			cipher_msg.plaintext_size_ = plain_msg.text_.size();
			paddingZeros(plain_msg.text_, cipher_msg.text_, block_bytesize);
			uint8_t *data_ptr = cipher_msg.text_.data();
			const size_t data_bytesize = cipher_msg.text_.size();

			encrypt(cipher_ptr, data_ptr, data_ptr, data_bytesize);
		}


		static void decrypt(const BlockCipherPtr cipher_ptr, const uint8_t *ciphertext, uint8_t *plaintext, const size_t data_bytesize)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (data_bytesize % block_bytesize != 0)
			{
				cerr << "Unpadded text!" << endl;
				return;
			}

			for (size_t i = 0; i < data_bytesize; i += block_bytesize)
			{
				cipher_ptr->decrypt(ciphertext + i, plaintext + i);
			}
		}

		static void decrypt(const BlockCipherPtr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			plain_msg.text_ = cipher_msg.text_;

			uint8_t *data_ptr = plain_msg.text_.data();
			const size_t data_bytesize = plain_msg.text_.size();

			decrypt(cipher_ptr, data_ptr, data_ptr, data_bytesize);

			plain_msg.plaintext_size_ = cipher_msg.plaintext_size_;
			plain_msg.text_.resize(plain_msg.plaintext_size_);
		}
};


class CTR
{
	public:
		template<typename IncrementFunction>
		static void createGamma(
				const BlockCipherPtr cipher_ptr,
				const uint8_t *iv,
				uint8_t *gamma,
				const size_t gamma_bytesize,
				IncrementFunction increment)
		{
			if (gamma_bytesize == 0)
			{
				cerr << "gamma_bytesize == 0" << endl;
				return;
			}
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();

			//uint8_t ctr[block_bytesize] = { 0x00 };
			vector<uint8_t> v_ctr(block_bytesize);
			uint8_t* ctr = v_ctr.data();

			memcpy(ctr, iv, block_bytesize);

			for (size_t i = 0; i + block_bytesize < gamma_bytesize; i += block_bytesize)
			{
				cipher_ptr->encrypt(ctr, gamma + i);
				increment(ctr, block_bytesize);
			}

			//uint8_t temp[block_bytesize] = {0x00};
			vector<uint8_t> v_temp(block_bytesize);
			uint8_t* temp = v_temp.data();

			cipher_ptr->encrypt(ctr, temp);

			size_t last_block_bytesize = getLastBlockBytesize(gamma_bytesize, block_bytesize);

			memcpy(gamma + gamma_bytesize - last_block_bytesize, temp, last_block_bytesize);
		}

		template<typename IncrementFunction>
		static void applyGamma(
						const BlockCipherPtr cipher_ptr,
						const uint8_t *iv,
						vector<uint8_t> &text,
						IncrementFunction increment)
		{
			const size_t data_bytesize = text.size();

			vector<uint8_t> gamma(data_bytesize, 0x00);
			CTR::createGamma(cipher_ptr, iv, gamma.data(), data_bytesize, increment);
			xorBlock(text.data(), text.data(), gamma.data(), data_bytesize);
		}


		static void encrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			size_t block_bytesize = cipher_ptr->getBlockByteSize();
			const size_t iv_size = block_bytesize / 2;
			if (plain_msg.nonce_.size() != iv_size)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}
			cipher_msg = plain_msg;
			//uint8_t iv[block_bytesize] = { 0x00 };
			vector<uint8_t> v_iv(block_bytesize);
			uint8_t* iv = v_iv.data();

			memcpy(iv, plain_msg.nonce_.data(), iv_size);
			applyGamma(cipher_ptr, iv, cipher_msg.text_, ctrIncrementRight);
		}

		static void decrypt(const BlockCipherPtr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			encrypt(cipher_ptr, cipher_msg, plain_msg);
		}
};


class CBC
{
	public:
		static void encrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (plain_msg.nonce_.size() != block_bytesize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}

			cipher_msg.nonce_ = plain_msg.nonce_;
			cipher_msg.plaintext_size_ = plain_msg.text_.size();
			paddingZeros(plain_msg.text_, cipher_msg.text_, block_bytesize);

			uint8_t *prev_block = cipher_msg.nonce_.data();

			const size_t data_bytesize = cipher_msg.text_.size();
			uint8_t *data_ptr = cipher_msg.text_.data();

			for (size_t i = 0; i < data_bytesize; i += block_bytesize)
			{
				xorBlock(data_ptr, data_ptr, prev_block, block_bytesize);
				cipher_ptr->encrypt(data_ptr, data_ptr);
				prev_block = data_ptr;
				data_ptr += block_bytesize;
			}
		}

		static void decrypt(const BlockCipherPtr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (plain_msg.nonce_.size() != block_bytesize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}

			plain_msg.nonce_ = cipher_msg.nonce_;
			plain_msg.text_ = cipher_msg.text_;

			const size_t data_bytesize = plain_msg.text_.size();
			uint8_t *data_ptr = plain_msg.text_.data();

			//uint8_t prev_block[block_bytesize];
			vector<uint8_t> v_prev_block(block_bytesize);
			uint8_t* prev_block = v_prev_block.data();

			memcpy(prev_block, plain_msg.nonce_.data(), block_bytesize);
			//uint8_t temp_block[block_bytesize];
			vector<uint8_t> v_temp_block(block_bytesize);
			uint8_t* temp_block = v_temp_block.data();

			for (size_t i = 0; i < data_bytesize; i += block_bytesize)
			{
				cipher_ptr->decrypt(data_ptr, temp_block);
				xorBlock(temp_block, temp_block, prev_block, block_bytesize);

				memcpy(prev_block, data_ptr, block_bytesize);
				memcpy(data_ptr, temp_block, block_bytesize);
				data_ptr += block_bytesize;
			}

			plain_msg.plaintext_size_ = cipher_msg.plaintext_size_;
			plain_msg.text_.resize(plain_msg.plaintext_size_);
		}
};


class CFB
{
	public:
		static void encrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (plain_msg.nonce_.size() != block_bytesize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}

			cipher_msg = plain_msg;

			//uint8_t temp_block[block_bytesize] = { 0x00 };
			vector<uint8_t> v_temp_block(block_bytesize);
			uint8_t* temp_block = v_temp_block.data();

			memcpy(temp_block, plain_msg.nonce_.data(), block_bytesize);

			const size_t data_bytesize = cipher_msg.text_.size();
			uint8_t *data_ptr = cipher_msg.text_.data();

			for (size_t i = 0; i + block_bytesize < data_bytesize; i += block_bytesize)
			{
				cipher_ptr->encrypt(temp_block, temp_block);
				xorBlock(data_ptr, data_ptr, temp_block, block_bytesize);
				memcpy(temp_block, data_ptr, block_bytesize);
				data_ptr += block_bytesize;
			}

			size_t last_block_bytesize = getLastBlockBytesize(data_bytesize, block_bytesize);
			cipher_ptr->encrypt(temp_block, temp_block);
			xorBlock(data_ptr, data_ptr, temp_block, last_block_bytesize);
		}

		static void decrypt(const BlockCipherPtr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (plain_msg.nonce_.size() != block_bytesize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}

			plain_msg = cipher_msg;

			const size_t data_bytesize = plain_msg.text_.size();
			uint8_t *data_ptr = plain_msg.text_.data();

			//uint8_t prev_block[block_bytesize];
			vector<uint8_t> v_prev_block(block_bytesize);
			uint8_t* prev_block = v_prev_block.data();

			memcpy(prev_block, plain_msg.nonce_.data(), block_bytesize);
			//uint8_t temp_block[block_bytesize];
			vector<uint8_t> v_temp_block(block_bytesize);
			uint8_t* temp_block = v_temp_block.data();

			for (size_t i = 0; i + block_bytesize < data_bytesize; i += block_bytesize)
			{
				cipher_ptr->encrypt(prev_block, temp_block);
				xorBlock(temp_block, temp_block, data_ptr, block_bytesize);
				memcpy(prev_block, data_ptr, block_bytesize);
				memcpy(data_ptr, temp_block, block_bytesize);
				data_ptr += block_bytesize;
			}

			size_t last_block_bytesize = getLastBlockBytesize(data_bytesize, block_bytesize);
			cipher_ptr->encrypt(prev_block, temp_block);
			xorBlock(data_ptr, data_ptr, temp_block, last_block_bytesize);
		}
};


class OFB
{
	public:
		static void encrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			if (plain_msg.nonce_.size() != block_bytesize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}
			cipher_msg = plain_msg;

			//uint8_t temp_block[block_bytesize] = { 0x00 };
			vector<uint8_t> v_temp_block(block_bytesize);
			uint8_t* temp_block = v_temp_block.data();

			memcpy(temp_block, plain_msg.nonce_.data(), block_bytesize);

			const size_t data_bytesize = cipher_msg.text_.size();
			uint8_t *data_ptr = cipher_msg.text_.data();

			for (size_t i = 0; i + block_bytesize < data_bytesize; i += block_bytesize)
			{
				cipher_ptr->encrypt(temp_block, temp_block);
				xorBlock(data_ptr, data_ptr, temp_block, block_bytesize);
				data_ptr += block_bytesize;
			}

			size_t last_block_bytesize = getLastBlockBytesize(data_bytesize, block_bytesize);
			cipher_ptr->encrypt(temp_block, temp_block);
			xorBlock(data_ptr, data_ptr, temp_block, last_block_bytesize);
		}

		static void decrypt(const BlockCipherPtr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			encrypt(cipher_ptr, cipher_msg, plain_msg);
		}
};


class CMAC
{
		static void keySchedule(const BlockCipherPtr cipher_ptr, uint8_t *key1, uint8_t *key2)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();

			//uint8_t blockR[block_bytesize] = { 0 };
			// 
			//std::shared_ptr<uint8_t> p_blockR = std::make_shared<uint8_t>(new uint8_t[block_bytesize]);
			//uint8_t* blockR = p_blockR.get();
			std::vector<uint8_t> v_blockR(block_bytesize);
			uint8_t* blockR = v_blockR.data();

			uint8_t polynomCoef = getPrimitivePolynomialCoef(block_bytesize * kBitInByte);

			cipher_ptr->encrypt(blockR, blockR); //R = E(0)

			bool msbR = msbBlock(blockR);
			blockLeftShift(blockR, block_bytesize); // R = R<<1

			if (msbR)
				blockR[block_bytesize - 1] ^= polynomCoef; //R = R xor Bn

			memcpy(key1, blockR, block_bytesize); //K1 = R

			memcpy(key2, blockR, block_bytesize); //K2 = R

			bool msb_key1 = msbBlock(key1);
			blockLeftShift(key2, block_bytesize); // K2 = K1 <<1

			if (msb_key1)
				key2[block_bytesize - 1] ^= polynomCoef; // K2 = K2 xor Bn
		}

	public:
		static void compute(const BlockCipherPtr cipher_ptr, Message &plain_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();

			//uint8_t key1[block_bytesize] = { 0x00 }; //case without padding
			vector<uint8_t> v_key1(block_bytesize);
			uint8_t* key1 = v_key1.data();


			//uint8_t key2[block_bytesize] = { 0x00 }; //case with padding
			vector<uint8_t> v_key2(block_bytesize);
			uint8_t* key2 = v_key2.data();

			keySchedule(cipher_ptr, key1, key2);

			uint8_t *data_ptr = plain_msg.text_.data();
			const size_t data_bytesize = plain_msg.text_.size();

			//uint8_t block[block_bytesize] = { 0x00 };
			vector<uint8_t> v_block(block_bytesize);
			uint8_t* block = v_block.data();

			for (size_t i = 0; i + block_bytesize < data_bytesize; i += block_bytesize)
			{
				xorBlock(block, block, data_ptr + i, block_bytesize);
				cipher_ptr->encrypt(block, block);
			}

			const size_t last_block_bytesize = data_bytesize % block_bytesize;

			if (last_block_bytesize == 0)
			{
				xorBlock(block, block, data_ptr + data_bytesize - block_bytesize, block_bytesize);

				xorBlock(block, block, key1, block_bytesize);

				cipher_ptr->encrypt(block, block);
			}
			else
			{
				xorBlock(block, block, data_ptr + data_bytesize - last_block_bytesize, last_block_bytesize);

				block[last_block_bytesize] ^= kMsbByteMask;

				xorBlock(block, block, key2, block_bytesize);

				cipher_ptr->encrypt(block, block);
			}

			plain_msg.mac_.resize(block_bytesize);
			memcpy(plain_msg.mac_.data(), block, block_bytesize);
		}

		static bool verify(const BlockCipherPtr cipher_ptr, Message &plain_msg)
		{
			auto mac = plain_msg.mac_;
			plain_msg.mac_.clear();
			compute(cipher_ptr, plain_msg);
			return mac == plain_msg.mac_;
		}
};


class MGM
{
		static void ctrEncrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();

			//uint8_t ctr[block_bytesize] = { 0x00 };
			vector<uint8_t> v_ctr(block_bytesize);
			uint8_t* ctr = v_ctr.data();


			memcpy(ctr, plain_msg.nonce_.data(), block_bytesize);
			setZeroMsb(ctr);
			cipher_ptr->encrypt(ctr, ctr);
			//ctr = E(0||nonce)

			CTR::applyGamma(cipher_ptr, ctr, cipher_msg.text_, ctrIncrementRight);
		}

		static size_t mixDataToMac(uint8_t *mac, const uint8_t *data, const uint8_t *blocksH, const size_t data_bytesize, const size_t block_bytesize)
		{
			//uint8_t temp_block[block_bytesize] = {0x00};
			vector<uint8_t> v_temp_block(block_bytesize);
			uint8_t* temp_block = v_temp_block.data();

			size_t i = 0;

			for (i = 0; i + block_bytesize < data_bytesize; i += block_bytesize)
			{
				fieldMultiplication(temp_block, blocksH + i, data + i, block_bytesize);
				xorBlock(mac, mac, temp_block, block_bytesize);
			}


			//uint8_t last_block[block_bytesize] = {0x00};
			vector<uint8_t> v_last_block(block_bytesize);
			uint8_t* last_block = v_last_block.data();

			const size_t last_block_bytesize = getLastBlockBytesize(data_bytesize, block_bytesize);

			memcpy(last_block, data + i, last_block_bytesize);

			fieldMultiplication(temp_block, blocksH + i, last_block, block_bytesize);
			xorBlock(mac, mac, temp_block, block_bytesize);
			i += block_bytesize;

			return i;
		}

		static void computeMAC(const BlockCipherPtr cipher_ptr, Message &cipher_msg)
		{
			const size_t block_bytesize = cipher_ptr->getBlockByteSize();
			const size_t auth_data_bytesize = cipher_msg.auth_data_.size();
			const size_t text_data_bytesize = cipher_msg.text_.size();

			const size_t auth_data_blocksize = bytesizeToBlocksize(auth_data_bytesize, block_bytesize);
			const size_t text_data_blocksize = bytesizeToBlocksize(text_data_bytesize, block_bytesize);
			const size_t total_blocksize = auth_data_blocksize + text_data_blocksize + 1;

			//uint8_t ctr[block_bytesize] = { 0x00 };
			vector<uint8_t> v_ctr(block_bytesize);
			uint8_t* ctr = v_ctr.data();

			memcpy(ctr, cipher_msg.nonce_.data(), block_bytesize);
			setOneMsb(ctr);
			cipher_ptr->encrypt(ctr, ctr);
			//ctr = E(1||nonce)

			vector<uint8_t> blocksH(total_blocksize * block_bytesize, 0x00);
			uint8_t *blocksH_ptr = blocksH.data();

			CTR::createGamma(cipher_ptr, ctr, blocksH_ptr, blocksH.size(), ctrIncrementLeft);

			cipher_msg.mac_ = vector<uint8_t>(block_bytesize, 0x00);
			uint8_t *mac_ptr = cipher_msg.mac_.data();

			blocksH_ptr += mixDataToMac(mac_ptr, cipher_msg.auth_data_.data(), blocksH_ptr, auth_data_bytesize, block_bytesize);
			blocksH_ptr += mixDataToMac(mac_ptr, cipher_msg.text_.data()     , blocksH_ptr, text_data_bytesize, block_bytesize);

			//lenBlock
			//uint8_t lenBlock[block_bytesize] = {0x00};
			vector<uint8_t> v_lenBlock(block_bytesize);
			uint8_t* lenBlock = v_lenBlock.data();

			uintToBlock(auth_data_bytesize * kBitInByte, lenBlock, block_bytesize/2);
			uintToBlock(text_data_bytesize * kBitInByte, lenBlock + block_bytesize/2, block_bytesize/2);

			blocksH_ptr += mixDataToMac(mac_ptr, lenBlock, blocksH_ptr, block_bytesize, block_bytesize);

			cipher_ptr->encrypt(mac_ptr, mac_ptr);
		}

		static bool verifyMAC(const BlockCipherPtr cipher_ptr, Message &cipher_msg)
		{
			auto mac = cipher_msg.mac_;
			cipher_msg.mac_.clear();
			computeMAC(cipher_ptr, cipher_msg);
			return mac == cipher_msg.mac_;
		}

	public:
		static void encrypt(const BlockCipherPtr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			if (plain_msg.nonce_.size() != cipher_ptr->getBlockByteSize())
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}
			cipher_msg = plain_msg;
			ctrEncrypt(cipher_ptr, cipher_msg, cipher_msg);
			computeMAC(cipher_ptr, cipher_msg);
		}

		static bool decrypt(const BlockCipherPtr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			if (plain_msg.nonce_.size() != cipher_ptr->getBlockByteSize())
			{
				cerr << "Non-valid length of IV!" << endl;
				return false;
			}

			plain_msg = cipher_msg;

			if (verifyMAC(cipher_ptr, plain_msg) == false)
				return false;

			ctrEncrypt(cipher_ptr, plain_msg, plain_msg);
			return true;
		}
};



class GOST89CTR
{

		static const size_t kBlockBytesize = GOST89::kBlockByteSize;

		static void increment(uint8_t *ctr, const size_t pseudo_arg = 0)
		{
			static const uint32_t constC1 = 0x1010104;
			static const uint32_t constC2 = 0x1010101;

			uint32_t a1 = GOST89::uint8ToUint32(ctr + GOST89::kBytesInWord);
			uint32_t a2 = GOST89::uint8ToUint32(ctr);

			a2 += constC2;
			uint64_t temp = uint64_t(a1) + uint64_t(constC1);
			a1 = temp % 0xFFFFFFFF;

			GOST89::uint32ToUint8(a1, ctr + GOST89::kBytesInWord);
			GOST89::uint32ToUint8(a2, ctr);
		}
	public:
		static void encrypt(const GOST89Ptr cipher_ptr, const Message &plain_msg, Message &cipher_msg)
		{
			if (plain_msg.nonce_.size() != kBlockBytesize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}
			cipher_msg = plain_msg;

			uint8_t ctr[kBlockBytesize] = { 0x00 };
			memcpy(ctr, plain_msg.nonce_.data(), kBlockBytesize);
			cipher_ptr->encrypt(ctr, ctr);
			increment(ctr);

			CTR::applyGamma(cipher_ptr, ctr, cipher_msg.text_, increment);
		}

		static void decrypt(const GOST89Ptr cipher_ptr, const Message &cipher_msg, Message &plain_msg)
		{
			encrypt(cipher_ptr, cipher_msg, plain_msg);
		}
};

class NefritC
{
		static const size_t kBlockByteSize = 16;
		static const size_t kNonceByteSize = 9;
		static const size_t kZeroBytesInCtr = 3;


		static void ctrEncrypt(const BlockCipherPtr cipher_ptr, Message &msg)
		{
			uint8_t ctr[kBlockByteSize] = { 0x00 };
			memcpy(ctr + kZeroBytesInCtr, msg.nonce_.data(), kNonceByteSize);
			ctr[kBlockByteSize - 1] = 0x01;
			//0x00,0x00,0x00,IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],0x00,0x00,0x00,0x01
			CTR::applyGamma(cipher_ptr, ctr, msg.text_, ctrIncrementRight);
		}

		static void mixDataToMac(uint8_t *mac, const uint8_t *data, const uint8_t *blockH, const size_t data_bytesize)
		{
			size_t i = 0;
			for (i = 0; i + kBlockByteSize < data_bytesize; i += kBlockByteSize)
			{
				xorBlock(mac, mac, data + i, kBlockByteSize);
				fieldMultiplication(mac, mac, blockH, kBlockByteSize);
			}

			uint8_t last_block[kBlockByteSize] = { 0x00 };

			const size_t last_block_bytesize = getLastBlockBytesize(data_bytesize, kBlockByteSize);

			memcpy(last_block, data + i, last_block_bytesize);

			if (last_block_bytesize < kBlockByteSize)
				last_block[last_block_bytesize] = kMsbByteMask;

			xorBlock(mac, mac, last_block, kBlockByteSize);
			fieldMultiplication(mac, mac, blockH, kBlockByteSize);
		}

		static void computeMAC(const BlockCipherPtr cipher_ptr, const GostKey auth_key, Message &msg)
		{
			const uint16_t auth_data_bytesize = msg.auth_data_.size();
			const uint32_t text_data_bytesize = msg.text_.size();

			uint8_t blockH[kBlockByteSize] = { 0x00 };
			cipher_ptr->encrypt(blockH, blockH);

			msg.mac_ = vector<uint8_t>(kBlockByteSize, 0x00);
			uint8_t *mac_ptr = msg.mac_.data();

			mixDataToMac(mac_ptr, msg.auth_data_.data(), blockH, auth_data_bytesize);
			mixDataToMac(mac_ptr, msg.text_.data(), blockH, text_data_bytesize);

			//Finalization
			uint8_t iv2Block[kBlockByteSize] = { 0x00 };
			memcpy(iv2Block, msg.nonce_.data(), kNonceByteSize);


			static const size_t kAuthByteLen = 2;
			static const size_t kPlaintextByteLen = 5;

			uintToBlock(auth_data_bytesize, iv2Block + kNonceByteSize, kAuthByteLen);
			uintToBlock(text_data_bytesize, iv2Block + kNonceByteSize + kAuthByteLen, kPlaintextByteLen);
			cipher_ptr->encrypt(auth_key, iv2Block, iv2Block);
			xorBlock(mac_ptr, mac_ptr, iv2Block, kBlockByteSize);
			cipher_ptr->encrypt(auth_key, mac_ptr, mac_ptr);
		}

		static bool verifyMAC(const BlockCipherPtr cipher_ptr, const GostKey auth_key, Message &cipher_msg)
		{
			auto mac = cipher_msg.mac_;
			cipher_msg.mac_.clear();
			computeMAC(cipher_ptr, auth_key, cipher_msg);
			return mac == cipher_msg.mac_;
		}

	public:
		static void encrypt(const BlockCipherPtr cipher_ptr, const GostKey auth_key, const Message &plain_msg, Message &cipher_msg)
		{
			if (plain_msg.nonce_.size() != kNonceByteSize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return;
			}
			cipher_msg = plain_msg;
			ctrEncrypt(cipher_ptr, cipher_msg);
			computeMAC(cipher_ptr, auth_key, cipher_msg);
		}

		static bool decrypt(const BlockCipherPtr cipher_ptr, const GostKey auth_key, const Message &cipher_msg, Message &plain_msg)
		{
			if (plain_msg.nonce_.size() != kNonceByteSize)
			{
				cerr << "Non-valid length of IV!" << endl;
				return false;
			}

			plain_msg = cipher_msg;

			if (verifyMAC(cipher_ptr, auth_key, plain_msg) == false)
				return false;

			ctrEncrypt(cipher_ptr, plain_msg);
			return true;
		}
};


#endif /* CIPHER_MODES_H_ */
