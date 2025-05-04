#include <iostream>
#include "./src/instrument/instrument.h"
#include "./src/hook/hook.h"

int main()
{

    printf("[+] Running..\n");

    hookLookup::populateFnsData();

    hookLookup::addHook("ZwAllocateVirtualMemory", [](PCONTEXT ctx, PVOID retAddr) {

        auto prochandle = hookLookup::getParam1<HANDLE>(ctx);
        auto ptrToAddress = hookLookup::getParam2<PVOID*>(ctx);
        auto pSize = hookLookup::getParam4<PSIZE_T>(ctx);
        auto protection = hookLookup::getParamN<ULONG>(ctx, 6);

        printf("Process Handle: %d, Pointer To Buffer: %p, Size: %ld, Protection: %d\n", prochandle, ptrToAddress, *pSize, protection);

        hookLookup::continueExecution(ctx, retAddr);
        
        });

    logsyscall::run();

    getchar();

    // ic will pick up on this and hook the NtAllocateVirtualMemory call
    VirtualAlloc(NULL, 30, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    getchar();

    // this call will be hooked
    VirtualAlloc(NULL, 69, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    system("pause");
}