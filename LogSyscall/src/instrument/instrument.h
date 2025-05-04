#pragma once

#include "./tls/tls.h"
#include "./ntapi/ntapi.h"
#include "../hook/hook.h"

constexpr DWORD PROCESS_INFO_CLASS_INSTRUMENTATION = 40;

typedef struct Trampoline {

	LPCSTR fnName;
	PVOID trampoline; // function that is redirected to after the EH sets the Rip to it, will need to jump back to syscall ret.

} Trampoline;

namespace logsyscall {

	static char patchSyscallArray[2] = { 0xCC, 0x90 };
	static char patchSyscallRetArray[3] = { 0x0f, 0x05, 0xc3 };

	void setVeh(PVECTORED_EXCEPTION_HANDLER exceptionHandler);
	bool setIc();
	bool run();
}
