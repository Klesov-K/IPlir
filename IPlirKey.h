#pragma once

// Шаблон IPlir-ключа
class IPlirKey
{
public:
	virtual void initKey(const vGostKey) = 0;
	virtual ~IPlirKey() {};

	vGostKey m_keychange;

private:

	virtual void keySchedule() = 0;

};


// Кузнечик
using IPlirKeyPtr = std::shared_ptr<IPlirKey>;

template<typename KeyType>
IPlirKeyPtr buildIPlirKey() {
	return std::make_shared<KeyType>();
}

template<typename KeyType>
IPlirKeyPtr buildIPlirKey(vGostKey vgostKey) {
	return std::make_shared<KeyType>(vgostKey);
}

//
// IntToVec8(i) || Label || aL || IVKDF || SN || Node || сL || oL,
//
struct IplirData {
	std::vector<UINT8> i;
	std::vector<UINT8> Label = {'E', 'N', 'C', 'M', 'A', 'C'};
	std::vector<UINT8> aL = {6};
	std::vector<UINT8> initValue;
	std::vector<UINT8> sn;
	std::vector<UINT8> Node;
	UINT16 cL = size(initValue) + size(sn) + size(Node);
	std::vector<UINT16> oL = { 512 };

};