
# LogSyscall

Windows x64 System Call Instrumention Engine.

## Explanation

LogSyscall allows you to instrument/hook system calls before they are executed.

It detects transitions from KM to UM using [Instrumention Callbacks](https://github.com/Deputation/instrumentation_callbacks), now that we have the return address we can place a software breakpoint on the ``syscall`` instruction.

Before the instrumention callback is even registered, we set up a [Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling/) that will allow us to catch our breakpoint exceptions.

The hook function supplied by the user early is run by the exception handler passing the CPU ``CONTEXT`` structure and an address that points to the syscall stub epilogue, which is what the function is gonna use to execute the system call after the instrumention.

This basically allows you to log/monitor any system call before it's executed.

## Code Examples

### SimpleHook | Hooking ZwOpenProcess & Modifying Access Mask
```cpp
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
```

### SuspiciousCall | Detecting Direct NTAPI Invocation
```cpp
engine::addHook("ZwAllocateVirtualMemory", [](PCONTEXT pCtx, PVOID syscallRet) {

        if (engine::detection::isDirectlyCalled(pCtx)) {

	   auto procHandle = engine::getParam1<HANDLE>(pCtx);
	   auto baseAddress = engine::getParam2<PVOID*>(pCtx);
	   auto pSize = engine::getParam4<PSIZE_T>(pCtx);
	   auto allocType = engine::getParam5<ULONG>(pCtx);
	   auto protection = engine::getParam6<ULONG>(pCtx);

	   printf("[!] Detected Suspicious ZwAllocateVirtualMemory Call (NTAPI / Direct Syscall / Indirect Syscall)\n");
        }
        
        engine::proceed(pCtx, syscallRet);

});
```

### DirectSyscall | Detecting Direct Syscall Invocation
```cpp
engine::addHook("ZwCreateThreadEx", [](PCONTEXT pCtx, PVOID syscallRet) { 
        
        if (engine::detection::isDirectSyscall(pCtx)) {

            auto pThread = engine::getParam1<PHANDLE>(pCtx);
            auto accessMask = engine::getParam2<ACCESS_MASK>(pCtx);
            auto procHandle = engine::getParam4<HANDLE>(pCtx);
            auto procAddress = engine::getParam5<PVOID>(pCtx);
            auto argument = engine::getParam6<PVOID>(pCtx);

            printf("[!] Detected ZwCreateThreadEx Direct Syscall..\n");

            engine::setParam6<const char*>(pCtx, "Hooked Argument!");

        }

        engine::proceed(pCtx, syscallRet);
});
```

## Usage
```
LogSyscall.exe <EXAMPLE_NAME>
```

## Usage Example
Running the ``DirectSyscall`` example:
```
$ LogSyscall.exe DirectSyscall
[*] Running [Direct System Call] Example..
[DemoFunction] Message: Hello!
Press any Key to Proceed.

[VEH] Calling Hook for Function 'ZwCreateThreadEx'
        Syscall Service Number: 199
[!] Detected ZwCreateThreadEx Direct Syscall..
        PThread: 0x000000F09758FB68
        Access Mask: 2097151
        Process Id: 61220
        Procedure Address: 0x00007FF791171410
        Argument: 0x00007FF7911745C8
[DemoFunction] Message: Hooked Argument!
```

## Todo
- Allow for detecting indirect system calls
- Allow for hooking ``ZwProtectVirtualMemory``
- Implement thread safety
- Implement post-syscall hooks

## Limitations & Issues
- ``ZwClose`` hooks throw an error with status code ``STATUS_STACK_BUFFER_OVERRUN`` 
- Can't hook ``ZwProtectVirtualMemory``

## Credits
[Instrumention Callbacks](https://github.com/Deputation/instrumentation_callbacks) by [Deputation](https://github.com/Deputation/).
