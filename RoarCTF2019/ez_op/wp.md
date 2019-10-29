静态链接，IDA加载18.04和18.10的sig文件，最终可以识别出很多libc库函数。
本题虽然能大概看出是VM，但原来对于VMP和VM等了解不够多，所以逆向时颇为费劲。
关键是识别出VM stack的结构体，然后对于PUSH、POP、LOAD、SAVE和其它加减乘除的指令解析就变得容易。

这里的漏洞主要是在`load_op`和`save_op`中，直接将临时stack上pop下来的两个操作数进行操作进行数据存取，而没有判断相应的偏移是否不合法。

逆向得到`system`的地址，并在`free`函数体中找到`__free_hook`地址，复写即可。

关键是计算得到任意写的起始地址到目标地址所需的偏移，gdb调试得到偏移为0x110 bytes
```
gef➤  x/100gx 0x0824c970
0x824c970:	0x0000000408051c60	0x0000000000000043 <= stack->data
0x824c980:	0x0000000000000000	0x0000000000000000
0x824c990:	0x0000000000000000	0x0000000000000000
0x824c9a0:	0x0000000000000000	0x0000000000000000
0x824c9b0:	0x0000000000000000	0x0000000000000000
0x824c9c0:	0x0000000000000000	0x0000000000000000
0x824c9d0:	0x0000000000000000	0x0000000000000000
0x824c9e0:	0x0000000000000000	0x0000000000000000
0x824c9f0:	0x0000000000000000	0x0000000000000000
0x824ca00:	0x0000000000000000	0x0000000000000000
0x824ca10:	0x0000000000000000	0x0000000000000000
0x824ca20:	0x0000000000000000	0x0000000000000000
0x824ca30:	0x0000000000000000	0x0000000000000000
0x824ca40:	0x0000000000000000	0x0000000000000000
0x824ca50:	0x0000000000000000	0x0000000000000000
0x824ca60:	0x0000000000000000	0x0000000000000000
0x824ca70:	0x0000000000000000	0x0000001100000000
0x824ca80:	0x000000400824c970	0x0002057900000001 <= stack->data[stack->cursor+offset] = stack_data
```
所以`offset = (0x110 / 4) - stack->cursor`