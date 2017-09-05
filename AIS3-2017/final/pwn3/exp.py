#!/usr/bin/env python
from pwn import *

DEBUG = True
if DEBUG:
    p = process("xorstr")

p.interactive()
p.close()
