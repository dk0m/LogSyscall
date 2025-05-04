#pragma once

#include<vector>
#include<optional>
#include "../pe/Pe.h"

using std::vector;

typedef VOID(*HookFnType) (PCONTEXT ctx, PVOID retAddr);

typedef struct HookData {
	HookFnType hook;
} HookData;

typedef struct NtFunction {

	LPCSTR name;
	WORD ordinal;
	PVOID address;
	DWORD ssn;

} NtFunction;

typedef struct HookEntry {
	NtFunction targetFn;
	HookData hookData;
} HookEntry;

namespace hookLookup {
	static Pe imgNtdll = ParsePeImage("ntdll.dll");
	static vector<NtFunction> fnsData;
	static vector<HookEntry> hooks;

	void populateFnsData();
	bool addHook(LPCSTR targetProc, HookFnType hook);

	bool hasHookEntry(DWORD fnSsn);
	std::optional<HookEntry> findHookEntryBySsn(DWORD targetSsn);

	template <typename T>
	T getParam1(PCONTEXT pContext) {
		return (T)pContext->Rcx;
	}

	template <typename T>
	T getParam2(PCONTEXT pContext) {
		return (T)pContext->Rdx;
	}

	template <typename T>
	T getParam3(PCONTEXT pContext) {
		return (T)pContext->R8;
	}

	template <typename T>
	T getParam4(PCONTEXT pContext) {
		return (T)pContext->R9;
	}

	template <typename T>
	T getParamN(PCONTEXT pContext, DWORD index) {
		return (T)*(ULONG_PTR*)(pContext->Rsp + (index * sizeof(PVOID)));
	}
	
	void continueExecution(PCONTEXT pContext, PVOID retAddr);
}
