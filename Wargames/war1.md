report.md

intro
===========================

Flag: (not found)

General overview of problems faced
-------------------------------------
spent too much time on 'too-slow'

to-slow
=============

~~Flag: (accidentally broke the remote machine)~~
Flag: COMP6447{2_SL0W_4_Y0U}

General overview of problems faced
-------------------------------------
Prob: AWS and Azure expired. Vigilant solution suggested does not seem
Soln: Had to install (L)Ubuntu on an old laptop. Jokes on me, I learnt a lot from installing ubuntu for the first time!

Prob: Obviously, can't hack 1001 from browser. #make_6447_morelike_6443 (just kidding)
Soln (bad): tried to do maths via Putty -> of course found myself not a Sonic
Soln (good): had to write a Python script

Prob: Python 3 branch of pwntools' installation instruction don't work!
Soln: Came up with my set of instructions (many of which are to work around bugs), will submit (push request) them onto branch ASAP

Prob: Contrary to docs, if you do r.recvuntil("crazystring") , crazystring gets appended to the result of operation
Soln: No biggie whatsoever. Will create an issue on Github

Prob: Dev3 (Python3) version of pwntools seems to be halfway broken (unexpected behaviour all the time):
Soln: Had to write script around problems

Prob: Spent DAYS trying to emulate shell
Soln: There exists bloody r.interactive() . It is glitchy sure, but seems stable enough . I'm so silly :)

**AND FINALLY**
Prob: Tried to tar the /flag directory -> broke the machine
Soln: ( ͡° ͜ʖ ͡°) . Told adamt about it

Script/Command used
------------------
```
print "#!/usr/bin/python3

from pwn import *

def main():
	PROGRAM_NAME = "1001"
	encoding = "ascii"
	r = remote('plzpwn.me', 1001)
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			r.recvuntil("math".encode(encoding))
			print("Math start!")
			r.recvuntil("out!\n".encode(encoding))
			stage = 1
		elif(stage == 1): #uses header
			header = r.recvn(1).decode(encoding)
			print("header: "+header)
			
			buf = header.isnumeric()
			
			if(header.isnumeric()): #is number? All good
				print("doing maths")
				
				buf = r.recvuntil("+".encode(encoding)).decode(encoding)[:-2]
				first = int(str(header)+buf.strip())
				print("first: "+str(first))
				
				buf = r.recvuntil("=".encode(encoding)).decode(encoding)[:-2]
				second = int(buf.strip())				
				print("second: "+str(second))
				
				result = str(first+second)
				print("result: "+str(result))
				
				r.sendline(result.encode(encoding))
				
				buf = r.recvuntil("Answer!\n".encode(encoding)).decode(encoding)
				print(buf)
			else:
				print("no more maths")
				stage = 2
		elif(stage == 2): #try for shell
			buf = r.recvline().decode(encoding)
			print("try anything")
			print(buf)
			r.sendline("secret".encode(encoding))
			
			print("waiting for a lil more")
			buf = r.recvline(timeout=10).decode(encoding)
			
			stage = 4
		elif(stage == 3):
			try:
				buf = str(raw_input(">>: ").decode(encoding))
				
				#print("input: "+buf)
				r.sendline(buf.encode(encoding))
				
				#buf = r.recv().decode(encoding)
				#print(buf)
				endofinput = 0
				while(not(endofinput)):
					try:
						buf = r.recv(timeout=2).decode(encoding)
						print(buf, end='')
					except Exception:
						endofinput = 1
						pass
					
			except KeyboardInterrupt:
				fin = 1
		elif(stage == 4):
			buf = r.interactive()
		else:
			print("Weird flex, exiting")
			fin = 1
			
	print("cya!")
			

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

if __name__ == '__main__':
	main()
	
"
```
Then
```
cat /flag
```

