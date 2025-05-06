#include <iostream>
#include "../../src/instrument/instrument.h"
#include "../../src/engine/engine.h"

#include "../examples.h"

typeNtAllocateVirtualMemory NtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("NTDLL"), "NtAllocateVirtualMemory");

void examples::runSuspiciousCall()
{
    printf("[*] Running [Suspicious Direct Call] Example..\n");

    engine::init();

    engine::addHook("ZwAllocateVirtualMemory", [](PCONTEXT pCtx, PVOID syscallRet) {

        if (engine::detection::isDirectlyCalled(pCtx)) {
		
		
	  auto procHandle = engine::getParam1<HANDLE>(pCtx);
          auto baseAddress = engine::getParam2<PVOID*>(pCtx);
          auto pSize = engine::getParam4<PSIZE_T>(pCtx);
          auto allocType = engine::getParam5<ULONG>(pCtx);
          auto protection = engine::getParam6<ULONG>(pCtx);

          printf("[!] Detected Suspicious ZwAllocateVirtualMemory Call (NTAPI / Direct Syscall / Indirect Syscall)\n");
          printf("\tProcess Id: %ld\n\tBase Address: 0x%p\n\tSize: %lld\n\tAllocation Type: %Id\n\tProtection: %I64d\n\n", procHandle, baseAddress, *pSize, allocType, protection);

        }
        
        engine::proceed(pCtx, syscallRet);

    });

    if (logsyscall::run()) {
        printf("[+] IC is Ready.\n");
    }

    // triggers the hooking (this won't be caught)
    VirtualAlloc(NULL, 69, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    PVOID allocReg = NULL;
    SIZE_T regSize = 150;

    printf("[*] Press any Key to Proceed.\n");
    getchar();

    // will be caught by our hook and deemed suspicious
    NtAllocateVirtualMemory(GetCurrentProcess(), &allocReg, 0, &regSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    system("pause");
}