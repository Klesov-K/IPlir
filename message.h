

#ifndef MESSAGE_H_
#define MESSAGE_H_

#include <cstdint>
#include <cstring>
#include <vector>

using std::uint8_t;
using std::vector;

struct Message
{
		vector<uint8_t> nonce_;
		vector<uint8_t> text_;
		vector<uint8_t> auth_data_;
		vector<uint8_t> mac_;
		size_t plaintext_size_;
};

#endif /* MESSAGE_H_ */
