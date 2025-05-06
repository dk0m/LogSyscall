#include "engine.h"

void engine::populateNtEntries() {
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

				ntEntries.push_back(NtFunction{
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

void engine::init() {
	engine::populateNtEntries();
}

bool engine::addHook(LPCSTR targetProc, HookFnType hook) {
	for (auto& fnData : ntEntries) {
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


bool engine::hasHookEntry(DWORD fnSsn) {
	for (auto& hook : hooks) {
		auto fnData = hook.targetFn;

		if (fnData.ssn == fnSsn) {
			return true;
		}
	}

	return false;
}

std::optional<HookEntry> engine::findHookEntryBySsn(DWORD targetSsn) {
	for (auto& hook : hooks) {
		auto fnData = hook.targetFn;

		if (fnData.ssn == targetSsn) {
			return std::make_optional<HookEntry>(hook);
		}
	}

	return std::nullopt;
}


ULONG_PTR engine::getReturnAddress(PCONTEXT pContext) {
	return (*(ULONG_PTR*)(pContext->Rsp));
}
ULONG_PTR engine::getInstructionPointer(PCONTEXT pContext) {
	return (ULONG_PTR)pContext->Rip;
}

bool engine::isAddressInImage(Pe& peImage, ULONG_PTR targetAddress) {
	ULONG_PTR imgBase = (ULONG_PTR)peImage.OptionalHeader.ImageBase;
	DWORD imageSize = peImage.OptionalHeader.SizeOfImage;

	ULONG_PTR imgEnd = (ULONG_PTR)(imgBase + imageSize);

	return (imgBase < targetAddress && targetAddress < imgEnd);
}

bool engine::isAddressInMainImage(ULONG_PTR targetAddress) {
	return isAddressInImage(currImg, targetAddress);
}

bool engine::isAddressInNtdll(ULONG_PTR targetAddress) {
	return isAddressInImage(imgNtdll, targetAddress);
}

void engine::proceed(PCONTEXT pContext, PVOID retAddr) {
	pContext->Rip = (DWORD64)retAddr;
	pContext->EFlags |= (1 << 16);
}

