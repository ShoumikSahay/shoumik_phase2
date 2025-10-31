# Module-Reverse Engineering
## Challenge 1-GDB Baby 1
## What I did
```
$ file debugger0_a
$ gdb debugger0_a
(gdb) info functions
(gdb) set disassembly-flavor intel
(gdb) disassemble main
(gdb) print 0x86342
this is the value that EAX contains-549698.
picoCTF{549698} is the flag
```
## Flag
picoCTF{549698}
## What I learned
I learned how to use basic GDB commands to inspect a binary and extract a flag. I ran file to identify the executable, used gdb and info functions to find useful symbols, switched to Intel disassembly syntax, and disassembled main to follow the program’s logic. By printing the value in the register (EAX) I could see the numeric result and convert it into the picoCTF flag format.
