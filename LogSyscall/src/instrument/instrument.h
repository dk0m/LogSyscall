#pragma once

#include "./tls/tls.h"
#include "./structs.h"
#include "../engine/engine.h"

constexpr DWORD PROCESS_INFO_CLASS_INSTRUMENTATION = 40;
constexpr DWORD STUB_SIZE = 25;

typedef struct Trampoline {
	LPCSTR fnName;
	PVOID trampoline;
} Trampoline;

namespace logsyscall {
	static PVOID syscallRetAddr = NULL;
	static BYTE patchSyscallArray[2] = { 0xCC, 0x90 };
	static BYTE patchSyscallRetArray[3] = { 0x0f, 0x05, 0xc3 };

	void setVeh(PVECTORED_EXCEPTION_HANDLER exceptionHandler);
	bool setIc();
	bool run();
}
