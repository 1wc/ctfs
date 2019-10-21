当溢出栈直到idx时，会写到溢出的idx去。如下面的算法，当我们覆盖到fake_counter之前时，此时fake_counter = 0x418，然后我们再写入一个字节，比如'a'，那么会将`fake_counter`覆盖为0x461，之后就会写入到栈上0x461的位置。所以我们要想覆盖rip，需要写一个0x28，那么也就覆盖到0x428，也就是[rbp-0x420]+8的位置。
```
while ( !feof(stdin) )
  {
    current_ch = fgetc(stdin);
    if ( current_ch == 10 )
      break;
    counter = fake_counter++;
    v6 = counter;
    buffer[counter] = current_ch;
  }
  buffer[fake_counter] = 0;

首先，题目禁用了execve系统调用，所以不能直接getshell，需要利用题目内置的ls方法获取flag的路径，然后直接写rop链读取flag。

能够想到的方法主要有两种：

1. ROP读取flag
2. 先ROP关闭NX，再写exp到bss段读取flag

但是第一种方法有些问题：题目需要构造open、read的syscall rop链，所以需要将open所打开的文件句柄rax传到rsi中，但尝试了很久时间并没有找到合适的gadgets。

所以还是采用第二种方案，先写到bss端上，然后调用mprotect函数修改为可执行，最后执行即可。

tip：在调用mprotect函数时，需要地址0x1000对齐，所以需要`& 0xfffffffffffff000`
