#include "./instrument.h"
#include<iostream>

extern "C" void Callback(PCONTEXT ctx);
extern "C" void bridge();

void patchSyscall(PVOID syscallInstr) {
	DWORD oldProtection;
	VirtualProtect(syscallInstr, 2, PAGE_EXECUTE_READWRITE, &oldProtection);

	memcpy(syscallInstr, logsyscall::patchSyscallArray, 2);

	VirtualProtect(syscallInstr, 2, oldProtection, &oldProtection);
}

LONG exceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		// TODO: add thread safety

		DWORD ssn = (DWORD)pExceptionInfo->ContextRecord->Rax;
		auto hookEntry = engine::findHookEntryBySsn(ssn).value();
		auto hookData = hookEntry.hookData;

		printf("[VEH] Calling Hook for Function '%s'\n\tSyscall Service Number: %ld\n", hookEntry.targetFn.name, ssn);

		hookData.hook(pExceptionInfo->ContextRecord, logsyscall::syscallRetAddr);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else {
		return EXCEPTION_CONTINUE_SEARCH;
	}
}


void Callback(PCONTEXT ctx) {
	uint64_t currentTeb = (uint64_t)NtCurrentTeb();

	ctx->Rip = *(uint64_t*)(currentTeb + 0x02d8);
	ctx->Rsp = *(uint64_t*)(currentTeb + 0x02e0);
	ctx->Rcx = ctx->R10;


	if (tls::isThreadHandlingSyscall()) {
		RtlRestoreContext(ctx, nullptr);
	}

	if (!tls::setThreadHandlingSyscall(true)) {
		RtlRestoreContext(ctx, nullptr);
	}

	PVOID returnAddress = (PVOID)ctx->Rip;
	DWORD returnValue = (DWORD)ctx->Rax;

	ULONG_PTR returnAddr = (ULONG_PTR)returnAddress;

	PVOID syscallInstr = NULL;

	DWORD ssn = 0;
	WORD offset = 0;

	while (offset <= STUB_SIZE) {

		if (*(PBYTE)(returnAddr - offset) == 0x0f && *(PBYTE)(returnAddr - (offset - 1)) == 0x05) {
			syscallInstr = (PVOID)(returnAddr - offset);

			if (syscallInstr == logsyscall::syscallRetAddr) {
				goto exit;
			}

		}

		if (*(PBYTE)(returnAddr - offset) == 0xB8) {
			ssn = *(PDWORD)(returnAddr - (offset - 1));
			break;
		}

		offset++;
	}

	if (!ssn) {
		goto exit;
	}

	// this nt function has a hook
	if (engine::hasHookEntry(ssn)) {
		patchSyscall(syscallInstr);
	}

exit:
	tls::setThreadHandlingSyscall(false);
	RtlRestoreContext(ctx, nullptr);
}

bool allocateRedirectStub() {
	logsyscall::syscallRetAddr = VirtualAlloc(NULL, 3, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(logsyscall::syscallRetAddr, &logsyscall::patchSyscallRetArray[0], 3);
	return logsyscall::syscallRetAddr != NULL;
}

void logsyscall::setVeh(PVECTORED_EXCEPTION_HANDLER exceptionHandler) {
	AddVectoredExceptionHandler(1, exceptionHandler);
}

typeNtSetInformationProcess NtSetInformationProcess = (typeNtSetInformationProcess)GetProcAddress(GetModuleHandleA("NTDLL"), "NtSetInformationProcess");

bool logsyscall::setIc() {
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;

	nirvana.Callback = (PVOID)(ULONG_PTR)bridge;
	nirvana.Reserved = 0;
	nirvana.Version = 0;

	NTSTATUS setIcStatus = NtSetInformationProcess(
		GetCurrentProcess(),
		(PROCESSINFOCLASS)PROCESS_INFO_CLASS_INSTRUMENTATION,
		&nirvana,
		sizeof(nirvana)
	);

	return NT_SUCCESS(setIcStatus);

}

bool logsyscall::run() {

	if (!allocateRedirectStub()) {
		return false;
	}

	logsyscall::setVeh(exceptionHandler);
	tls::initTlsValue();

	if (logsyscall::setIc()) {
		return true;
	}
	else {
		return false;
	}
}