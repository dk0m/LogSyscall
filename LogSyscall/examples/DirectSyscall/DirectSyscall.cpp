#include <iostream>
#include "../../src/instrument/instrument.h"
#include "./syswhispers/Syscalls.h"

#include "../examples.h"

void DemoFunction(const char* message) {
    printf("[DemoFunction] Message: %s\n", message);
}

void examples::runDirectSyscall() {
	
    printf("[*] Running [Direct System Call] Example..\n");

    engine::init();

    engine::addHook("ZwCreateThreadEx", [](PCONTEXT pCtx, PVOID syscallRet) { 
        
        if (engine::detection::isDirectSyscall(pCtx)) {

            auto pThread = engine::getParam1<PHANDLE>(pCtx);
            auto accessMask = engine::getParam2<ACCESS_MASK>(pCtx);
            auto procHandle = engine::getParam4<HANDLE>(pCtx);
            auto procAddress = engine::getParam5<PVOID>(pCtx);
            auto argument = engine::getParam6<PVOID>(pCtx);

            printf("[!] Detected ZwCreateThreadEx Direct Syscall..\n");
            printf("\tPThread: 0x%p\n\tAccess Mask: %ld\n\tProcess Id: %ld\n\tProcedure Address: 0x%p\n\tArgument: 0x%p\n", pThread, accessMask, GetProcessId(procHandle), procAddress, argument);

            engine::setParam6<const char*>(pCtx, "Hooked Argument!");

        }

        engine::proceed(pCtx, syscallRet);
    });

    logsyscall::run();

    HANDLE firstThread = NULL;
    const char* firstMessage = "Hello!";

    // triggers the hooking (this won't be caught)
    Ds_NtCreateThreadEx(
        &firstThread,
        0x1FFFFF,
        NULL,
        GetCurrentProcess(),
        DemoFunction,
        (PVOID)firstMessage,
        0,
        0,
        0,
        0,
        NULL
    );
    WaitForSingleObject(firstThread, INFINITE);

    printf("Press any Key to Proceed.\n");
    getchar();

    HANDLE secondThread = NULL;
    const char* secondMessage = "Hello Again (You Won't See This)";

    // will be caught by our hook
    Ds_NtCreateThreadEx(
        &secondThread,
        0x1FFFFF,
        NULL,
        GetCurrentProcess(),
        DemoFunction,
        (PVOID)secondMessage,
        0,
        0,
        0,
        0,
        NULL
    );

    WaitForSingleObject(secondThread, INFINITE);

    system("pause");
}