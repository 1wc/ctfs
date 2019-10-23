防护均开启

> **realloc**
> 函数原型为**realloc(ptr, size)**，其中**ptr**为指向堆的指针，**size**为需要**realloc**的大小，根据**size**的大小有以下几种情况：
>
> - **size = 0**时，相当于**free(ptr)**。
> - **size < ptr原大小**时，会将原**chunk**分割为两部分，**free**掉后面的**chunk**。
> - **size = ptr原大小**时，没什么卵用，不会进行任何操作。**注：该等于为将size对齐后相等。**
> - **size > ptr原大小**时，若**ptr**下方为**top chunk**或者下方存在**fastbin**之外的**free chunk**并且**size(free chunk) + size(ptr原大小) ≥ size**，则将该堆块大小扩展至**size**，若不满足上述条件，则相当于**free(ptr)**然后**malloc(size)**。

### leak libc

该题没有show函数，所以需要通过stdout进行泄漏。

覆盖为0xfbad1887 + p64(0)*3即可

stdout如下：

```
gef➤  p  *(struct _IO_FILE_plus *) stdout
$1 = {
  file = {
    _flags = 0xfbad2887, 
    _IO_read_ptr = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_end = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_base = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_base = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_ptr = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_end = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_base = 0x7f4b20f7f7e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_end = 0x7f4b20f7f7e4 <_IO_2_1_stdout_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7f4b20f7ea00 <_IO_2_1_stdin_>, 
    _fileno = 0x1, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffffffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "\n", 
    _lock = 0x7f4b20f808c0 <_IO_stdfile_1_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0x7f4b20f7e8c0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0xffffffff, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7f4b20f7b2a0 <_IO_file_jumps>
}

```

首先构造三个chunk，0x70（chunk0）、0x100（chunk1）、0xe0，分别用先realloc再realloc(0x0)的方法free掉。

再次从tcache中取出0x100的chunk（realloc(0x100)），然后free 7次填满tcache，最后再realloc(0x0)的时候，就会将chunk1同时放到unsorted bin和tcache中。

之后再realloc(0x70)，令指针指向chunk0的位置，由于chunk1此时被free，所以我们realloc(0x180)正好可以构造overlapping，从而任意修改chunk1。

我们利用这一点，令chunk1的fd指向stdout（需要爆破），然后就可以申请到stdout上伪造IO_file结构体，泄漏libc。

泄漏成功后，用后门函数重置堆，然后再按照上述步骤劫持`__free_hook`为one_shot即可getshell。
