
# LogSyscall

Windows System Call Instrumention Engine Using ICs.

## Explanation
LogSyscall allows you to instrument/hook system calls before they are executed.

It detects transitions from KM to UM using [Instrumention Callbacks](https://github.com/Deputation/instrumentation_callbacks), now that we have the return address we can place a software breakpoint on the ``syscall`` instruction.

Before the instrumention callback is even registered, we set up a [Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling/) that will allow us to catch our breakpoint exceptions.

The hook function supplied by the user early is run by the exception handler passing the CPU ``CONTEXT`` structure and an address that points to the syscall stub epilogue, which is what the function is gonna use to execute the system call after the instrumention.

This basically allows you to log/monitor any system call before it's executed.

## Example

Hooking [ZwAllocateVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)

```cpp
hookLookup::addHook("ZwAllocateVirtualMemory", [](PCONTEXT ctx, PVOID retAddr) {

        auto prochandle = hookLookup::getParam1<HANDLE>(ctx);
        auto ptrToAddress = hookLookup::getParam2<PVOID*>(ctx);
        auto pSize = hookLookup::getParam4<PSIZE_T>(ctx);
        auto protection = hookLookup::getParamN<ULONG>(ctx, 6);

        printf("Process Handle: %d, Pointer To Buffer: %p, Size: %ld, Protection: %d\n", prochandle, ptrToAddress, *pSize, protection);

        hookLookup::continueExecution(ctx, retAddr);
        
        });
```

## Todo

- Make functions for modifying parameters / return value
- Implement thread safety
- Make an examples directory

## Credits

[Instrumention Callbacks](https://github.com/Deputation/instrumentation_callbacks) by [Deputation](https://github.com/Deputation/).
