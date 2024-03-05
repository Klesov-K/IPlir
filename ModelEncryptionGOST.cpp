//============================================================================
// Name        : ModelEncryptionGOST.cpp
// Author      : V.A.Kiryukhin
// Version     :
// Copyright   : JSC InfoTeCS 2020
//============================================================================

#include "cipher_base.h"
#include "common.h"
#include "stdafx.h"
#include "magma.h"
#include "kuznyechik.h"
#include "cipher_modes.h"
#include "message.h"
#include "test.h"

//#include "L2/test.h"

int main()
{
	cout << "ModelEncryptionGOST" << endl;

	//test_magma();

	//test_kuznyechik();

	//test_cmac_kuznyechik();

	test_ctr_kuznyechik();

	//test_mgm_magma();
	
	//test_gost89ctr();


	cout << "exit..." << endl;

	return 0;
}
