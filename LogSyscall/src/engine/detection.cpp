#include "engine.h"

// next version (V3) will implement indirect syscall detection.

bool engine::detection::isDirectlyCalled(PCONTEXT pContext) {
	auto retAddr = engine::getReturnAddress(pContext);
	return engine::isAddressInMainImage(retAddr);
}

bool engine::detection::isDirectSyscall(PCONTEXT pContext) {
	auto rip = engine::getInstructionPointer(pContext);
	return isDirectlyCalled(pContext) && !engine::isAddressInNtdll(rip);
}