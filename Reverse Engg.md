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
## Challenge 3-Vault door 3
## What I did
```
The program reads an input of the form picoCTF{<password>} and passes the substring <password> (length 32 expected) to checkPassword(). That method builds a 32-char buffer by reading characters from the input password with four different index patterns, then compares new String(buffer) with the fixed target: jU5t_a_sna_3lpm18gb41_u_4_mfr340
The solution is to invert the buffer construction to recover the original password that, after rearrangement, equals the target.
// extracts user input between picoCTF{ and }
String input = userInput.substring("picoCTF{".length(), userInput.length()-1);

public boolean checkPassword(String password) {
    if (password.length() != 32) {
        return false;
    }
    char[] buffer = new char[32];
    int i;
    for (i=0; i<8; i++) {
        buffer[i] = password.charAt(i);
    }
    for (; i<16; i++) {
        buffer[i] = password.charAt(23-i);
    }
    for (; i<32; i+=2) {
        buffer[i] = password.charAt(46-i);
    }
    for (i=31; i>=17; i-=2) {
        buffer[i] = password.charAt(i);
    }
    return new String(buffer).equals("jU5t_a_sna_3lpm18gb41_u_4_mfr340");
}
RECONSTRUCTION SCRIPT-
target = list("jU5t_a_sna_3lpm18gb41_u_4_mfr340")
password = ['?'] * 32

# Loop A inverse: i = 0..7
for i in range(0, 8):
    password[i] = target[i]

# Loop B inverse: i = 8..15 -> password[23 - i] = target[i]
for i in range(8, 16):
    password[23 - i] = target[i]

# Loop C inverse: i = 16,18,...,30 -> password[46 - i] = target[i]
for i in range(16, 32, 2):
    password[46 - i] = target[i]

# Loop D inverse: i = 31,29,...,17 -> password[i] = target[i]
for i in range(31, 16, -2):
    password[i] = target[i]

recovered = "".join(password)
print(recovered)

OUTPUT-jU5t_a_s1mpl3_an4gr4m_4_u_1fb380

```
## Flag
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_1fb380}

## What I learned
I learned how to carefully read and reverse-engineer Java code by understanding how loops and index manipulation work. I realized that even though the program looked complicated at first, breaking it down into small logical steps made it much easier to follow. I also learned how to invert operations to reconstruct the original input and how to verify my results using a simple Python script.
