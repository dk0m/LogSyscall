#include "hook.h"

void hookLookup::populateFnsData() {
	auto baseNtdll = imgNtdll.OptionalHeader.ImageBase;

	auto expDir = imgNtdll.ExportDirectory;
	auto rtf = imgNtdll.RunTimeEntryTable;

	PDWORD addrOfNameRvas = (PDWORD)(baseNtdll + expDir->AddressOfNames);
	PWORD addrOfOrds = (PWORD)(baseNtdll + expDir->AddressOfNameOrdinals);
	PDWORD addrOfFnRvas = (PDWORD)(baseNtdll + expDir->AddressOfFunctions);

	DWORD index = 0;
	DWORD ssn = 0;

	while (rtf[index].BeginAddress) {

		for (size_t i = 0; i < expDir->NumberOfFunctions; i++)
		{
			LPCSTR fnName = (LPCSTR)(baseNtdll + addrOfNameRvas[i]);

			if (strncmp(fnName, "Zw", 2))
				continue;

			WORD fnOrd = addrOfOrds[i];
			DWORD fnRva = addrOfFnRvas[fnOrd];


			if (fnRva == rtf[index].BeginAddress) {

				fnsData.push_back(NtFunction{
					fnName,
					fnOrd,
					(PVOID)(baseNtdll + fnRva),
					ssn
					});

				ssn++;
			}

		}

		index++;
	}

}

bool hookLookup::addHook(LPCSTR targetProc, HookFnType hook) {
	for (auto& fnData : fnsData) {
		if (!strcmp(fnData.name, targetProc)) {

			auto hookData = HookData{
				hook
			};

			hooks.push_back(
				HookEntry {
					fnData,
					hookData
				}
			);

		}
	}

	return true;
}


bool hookLookup::hasHookEntry(DWORD fnSsn) {
	for (auto& hook : hooks) {
		auto fnData = hook.targetFn;

		if (fnData.ssn == fnSsn) {
			return true;
		}
	}

	return false;
}

std::optional<HookEntry> hookLookup::findHookEntryBySsn(DWORD targetSsn) {
	for (auto& hook : hooks) {
		auto fnData = hook.targetFn;

		if (fnData.ssn == targetSsn) {
			return std::make_optional<HookEntry>(hook);
		}
	}

	return std::nullopt;
}

void hookLookup::continueExecution(PCONTEXT pContext, PVOID retAddr) {
	pContext->Rip = (DWORD64)retAddr;
	pContext->EFlags |= (1 << 16);
}