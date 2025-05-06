.code

Ds_NtCreateThreadEx PROC
	mov r10, rcx
	mov eax, 199 ; hardcoded SSN for the sake of simplicity
	syscall
	ret
Ds_NtCreateThreadEx ENDP

end