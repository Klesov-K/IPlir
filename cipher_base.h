/*
 * cipher.h
 *
 *  Created on: Jan 27, 2020
 *      Author: V.A.Kiryukhin
 */

#ifndef CIPHER_BASE_H_
#define CIPHER_BASE_H_

#include <cstdint>
#include <memory>

using std::size_t;
using std::uint8_t;

class BlockCipher
{
	public:
		virtual void initKey(const uint8_t *key) = 0;
		virtual void encrypt(const uint8_t *plain_block , uint8_t *cipher_block) const = 0;
		virtual void decrypt(const uint8_t *cipher_block, uint8_t *plain_block) const = 0;
		virtual void encrypt(const uint8_t *key, const uint8_t *plain_block , uint8_t *cipher_block) const = 0;
		virtual void decrypt(const uint8_t *key, const uint8_t *cipher_block, uint8_t *plain_block) const = 0;
		virtual size_t getBlockByteSize() const = 0;
		virtual ~BlockCipher(){}
};

using BlockCipherPtr = std::shared_ptr<BlockCipher>;

template<typename CipherType>
BlockCipherPtr buildBlockCipher()
{
	return std::make_shared<CipherType>();
}

template<typename CipherType>
BlockCipherPtr buildBlockCipher(const uint8_t *key)
{
	return std::make_shared<CipherType>(key);
}

#endif /* CIPHER_BASE_H_ */
