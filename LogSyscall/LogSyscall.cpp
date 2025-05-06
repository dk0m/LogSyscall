#include <iostream>
#include "./examples/examples.h"

int main(int argc, char* argv[])
{
	const char* selectedExample = argv[1];

	if (!selectedExample) {
		printf("[-] Please Select an Example.\n");
		return -1;
	}

	if (!_stricmp(selectedExample, "SuspiciousCall")) {
		examples::runSuspiciousCall();
	}
	else if (!_stricmp(selectedExample, "SimpleHook")) {
		examples::runSimpleHook();
	}
	else if (!_stricmp(selectedExample, "DirectSyscall")) {
		examples::runDirectSyscall();
	}
}