#pragma once

#include<vector>
#include<optional>
#include "../pe/Pe.h"

using std::vector;
using std::optional;

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

namespace engine {
	static Pe imgNtdll = ParsePeImage("ntdll.dll");
	static Pe currImg = ParsePeImage(NULL);

	static vector<NtFunction> ntEntries;
	static vector<HookEntry> hooks;

	void populateNtEntries();
	void init();

	bool addHook(LPCSTR targetProc, HookFnType hook);
	bool hasHookEntry(DWORD fnSsn);

	optional<HookEntry> findHookEntryBySsn(DWORD targetSsn);

	// GET PARAM //

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

	template <typename T>
	T getParam5(PCONTEXT pContext) {
		return getParamN<T>(pContext, 5);
	}

	template <typename T>
	T getParam6(PCONTEXT pContext) {
		return getParamN<T>(pContext, 6);
	}

	template <typename T>
	T getParam7(PCONTEXT pContext) {
		return getParamN<T>(pContext, 7);
	}
	
	template <typename T>
	T getParam8(PCONTEXT pContext) {
		return getParamN<T>(pContext, 8);
	}

	template <typename T>
	T getParam9(PCONTEXT pContext) {
		return getParamN<T>(pContext, 9);
	}

	template <typename T>
	T getParam10(PCONTEXT pContext) {
		return getParamN<T>(pContext, 10);
	}


	// SET PARAM //

	template <typename T>
	void setParam1(PCONTEXT pContext, T value) {
		pContext->Rcx = (DWORD64)value;
	}

	template <typename T>
	void setParam2(PCONTEXT pContext, T value) {
		pContext->Rdx = (DWORD64)value;
	}

	template <typename T>
	void setParam3(PCONTEXT pContext, T value) {
		pContext->R8 = (DWORD64)value;
	}

	template <typename T>
	void setParam4(PCONTEXT pContext, T value) {
		pContext->R9 = (DWORD64)value;
	}

	template <typename T>
	void setParamN(PCONTEXT pContext, T value, DWORD index) {
		*(ULONG_PTR*)(pContext->Rsp + (index * sizeof(PVOID))) = (DWORD64)value;
	}

	template <typename T>
	void setParam5(PCONTEXT pContext, T value) {
		setParamN(pContext, value, 5);
	}

	template <typename T>
	void setParam6(PCONTEXT pContext, T value) {
		setParamN(pContext, value, 6);
	}

	template <typename T>
	void setParam7(PCONTEXT pContext, T value) {
		setParamN(pContext, value, 7);
	}

	template <typename T>
	void setParam8(PCONTEXT pContext, T value) {
		setParamN(pContext, value, 8);
	}

	template <typename T>
	void setParam9(PCONTEXT pContext, T value) {
		setParamN(pContext, value, 9);
	}

	template <typename T>
	void setParam10(PCONTEXT pContext, T value) {
		setParamN(pContext, value, 10);
	}

	ULONG_PTR getReturnAddress(PCONTEXT pContext);
	ULONG_PTR getInstructionPointer(PCONTEXT pContext);

	bool isAddressInImage(Pe& peImage, ULONG_PTR targetAddress);

	bool isAddressInMainImage(ULONG_PTR targetAddress);
	bool isAddressInNtdll(ULONG_PTR targetAddress);

	void proceed(PCONTEXT pContext, PVOID retAddr);

	namespace detection {

		bool isDirectlyCalled(PCONTEXT pContext);
		bool isDirectSyscall(PCONTEXT pContext);

	}
}
