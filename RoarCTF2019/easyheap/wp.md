没有开启PIE，别的防护全部开启

一开始会向bss段上写两个0x20 bytes

存在后门函数，可以calloc一个0xa0的chunk，或者free它。这两个free中都存在UAF漏洞，没有置空bss段上的指针

就是构造double free，然后fastbin attack或者tcache attack即可。注意在leak出libc之后，会close掉stdout和stderr

