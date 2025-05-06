#include <iostream>
#include "../../src/instrument/instrument.h"
#include "../../src/engine/engine.h"

#include "../examples.h"

#include<winternl.h>

bool hasFlag(ACCESS_MASK accessMask, DWORD flag) {
	return ((accessMask & flag) == flag);
}

void examples::runSimpleHook() {

	printf("[*] Running [Simple Hook] Example..\n");

	engine::init();

	engine::addHook("ZwOpenProcess", [](PCONTEXT pCtx, PVOID syscallRet) {

		auto pHandle = engine::getParam1<PHANDLE>(pCtx);
		auto accessMask = engine::getParam2<ACCESS_MASK>(pCtx);
		auto objAttrs = engine::getParam3<POBJECT_ATTRIBUTES>(pCtx);
		auto clientId = engine::getParam4<CLIENT_ID*>(pCtx);
		
		printf("[*] Detected ZwOpenProcess Call..\n");
		printf("\tPHandle: 0x%p\n\tAccess Mask: %ld\n\tObject Attributes: 0x%p\n\tProcess Id: %ld\n", pHandle, accessMask, objAttrs,(DWORD)clientId->UniqueProcess);

		if (hasFlag(accessMask, PROCESS_TERMINATE)) {
			printf("[*] Found PROCESS_TERMINATE Flag, Removing it..\n");
			accessMask &= ~PROCESS_TERMINATE;

			engine::setParam2<ACCESS_MASK>(pCtx, accessMask);
		}

		engine::proceed(pCtx, syscallRet);
	});

	if (logsyscall::run()) {
		printf("[+] IC is Ready.\n");
	}
	
	DWORD procId = 10656; // place a valid pid
	
	// triggers the hooking (this won't be caught)
	HANDLE procHandle = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		procId
	);
	
	printf("Press any Key to Proceed.\n");
	getchar();

	// will be caught by our hook
	procHandle = OpenProcess(
		PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_TERMINATE,
		FALSE,
		procId
	);

	// won't work since the PROCESS_TERMINATE flag is stripped by our hook
	// LastError will be ERROR_ACCESS_DENIED (5)

	if (!TerminateProcess(procHandle, 0)) {
		printf("[-] Couldn't Terminate Process, Last Error: %ld\n", GetLastError());
	}
	system("pause");
}