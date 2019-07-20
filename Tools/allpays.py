#python2

from pwn import *

context.binary = './ropme'

f = open("sh.pot", "w+")
f.write(shellcraft.sh())
f.close()

f = open("crash.pot", "w+")
f.write(shellcraft.crash())
f.close()

f = open("eip.pot", "w+")
f.write(shellcraft.getpc())
f.close()

f = open("nop.pot", "w+")
f.write(shellcraft.nop())
f.close()

f = open("echo.pot", "w+")
f.write(shellcraft.echo("pw0 world"))
f.close()

print("All done")