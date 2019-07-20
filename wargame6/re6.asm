extern malloc
extern exit

global    _start
global _realstart

section .code
.global function
_start:
call _realstart
mov ebx, eax 


_realstart:
.global function
push ebp
mov ebp, esp
sub esp, 12
mov dword [ebp-12], 0
mov dword [ebp-8], 0
jmp short loc_80491DE

loc_80491DE:
cmp dword [ebp-8], 9
jle short loc_804918C

mov eax, [ebp-12]
leave
retn
;} //starts at 8049176 
;new endp

loc_804918C:	; size
push 8
call malloc
add esp, 4
mov dword [ebp-8], eax
cmp dword [ebp-8], 0
jnz short loc_80491A6

push 1	; status
call exit

loc_80491A6:
cmp dword [ebp-12], 0
jnz short loc_80491B4

mov eax, [ebp-8] 
mov [ebp-12], eax
jmp short loc_80491C3

loc_80491B4:
mov eax, [ebp-8]
mov edx, [ebp-12]
mov [eax+4], edx
mov eax, [ebp-8]
mov [ebp-12], eax


loc_80491C3:
mov eax, [ebp-8]
mov dword [eax+4], 0
mov eax, [ebp-8]
add eax, 65
mov edx, eax
mov eax, [ebp-8]
mov [eax], dl
add dword [ebp-8], 1

ret
;// check for: [* .]