
#include "IPlirKey.h"
#include "stdafx.h"



class IPlirKuznKey : public IPlirKey {
	vGostKey m_keyenc;
	vGostKey m_keymac;
	IPlirKuznKey(const vGostKey &vgostKey) {
		initKey(vgostKey);
	}

	virtual void keySchedule() {
		
	}

	virtual void initKey(const vGostKey &vgostKey) {
		m_keychange = vgostKey;
		keySchedule();
	}
};