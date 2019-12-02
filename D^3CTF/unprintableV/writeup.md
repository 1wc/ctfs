## unprintableV

防护除了canary全部开启。题目中有一个沙箱函数，我们可以用david942j dl开源的[seccomp-tools](https://github.com/david942j/seccomp-tools)分析一下。

```shell
$ sudo gem install seccomp-tools
liwc@ubuntu:~/pwn/ctfs/D^3CTF/unprintableV$ seccomp-tools dump ./unprintableV
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL

```

禁用了`execve`函数，所以应该使用`open`,`read`,`write`等函数组合读取flag。

题目会leak出栈上的地址。在向栈上输入`D^3CTF`之后会调用漏洞函数，这里存在明显的格式化字符串漏洞，但是这个格式化字符串在bss段，所以要利用的话要麻烦些。

```c
void __cdecl vuln()
{
  read(0, buf, 0x12CuLL);
  printf(buf, buf);
  --time;
}
```

题目的主要难点是该题中调用`close(1)`关闭了stdout，所以没有回显。这里出题人给了两种方法，比较好理解的一种是把stdout覆盖成stderr，这里由于pie的存在需要爆破低2个字节（成功率1/16）。

```
gef➤  x/32gx buf-0x40
0x555555756020 <stdout@@GLIBC_2.2.5>:	0x00007ffff7dd2620	0x0000000000000000
0x555555756030 <stdin@@GLIBC_2.2.5>:	0x00007ffff7dd18e0	0x0000000000000000
0x555555756040 <stderr@@GLIBC_2.2.5>:	0x00007ffff7dd2540	0x0000000000000000

```

我们在调试时先关掉ASLR，然后nop掉close(1)测一下偏移：

```assembly
gef➤  dereference $rsp 30
0x00007fffffffdc88│+0x0000: 0x0000555555554a14  →   lea rdi, [rip+0x201645]        # 0x555555756060	 ← $rsp # 偏移5
0x00007fffffffdc90│+0x0008: 0x00007fffffffdcb0  →  0x00007fffffffdcd0  →  0x0000555555554b60  →   push r15	 ← $rbp # 偏移6
0x00007fffffffdc98│+0x0010: 0x0000555555554afb  →   mov edx, 0x6 # 偏移7
0x00007fffffffdca0│+0x0018: 0x7fff000000000006 # 偏移8
0x00007fffffffdca8│+0x0020: 0x0000555555756060  →  0x0000000000000000 # 偏移9 leak处的栈地址
0x00007fffffffdcb0│+0x0028: 0x00007fffffffdcd0  →  0x0000555555554b60  →   push r15 # 偏移10
0x00007fffffffdcb8│+0x0030: 0x0000555555554b51  →   mov eax, 0x0
0x00007fffffffdcc0│+0x0038: 0x00007fffffffddb8  →  0x00007fffffffe162  →  "./unprintableV"
0x00007fffffffdcc8│+0x0040: 0x0000000100000000
0x00007fffffffdcd0│+0x0048: 0x0000555555554b60  →   push r15 # main函数saved ebp 偏移14
0x00007fffffffdcd8│+0x0050: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax # main函数返回地址 偏移15
0x00007fffffffdce0│+0x0058: 0x0000000000000001
0x00007fffffffdce8│+0x0060: 0x00007fffffffddb8  →  0x00007fffffffe162  →  "./unprintableV"

```

可以看到偏移6处指向栈上地址，我们将这个地址覆盖为a的地址，`%6$hhn`。然后再`%10$hhn`就可以复写buf的地址为stdout。这里实际上在栈上构造了一个**任意写漏洞**。

爆破成功后，我们就可以从栈中leak libc和程序的加载基址。

之后，应该选择在bss端构造rop链，然后stack pivoting。

采用fake frame手法，利用刚才的任意写漏洞将main函数saved rbp覆盖为fake rbp，再将main返回地址覆盖为leave ret的gadget地址，最终就会将控制流劫持到bss端！ 













