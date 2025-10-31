# Module-Forensics
## Challenge 1-tunn3l v1s10n
## What I did
```
Intro
One surgical procedure for the ethical hacker is to use scalpel to fix tunn3l v1s10n.

Tool: Scalpel
In the /etc/scalpel/scalpel.conf configuration file of the scalpel tool, uncomment the following line:

#       bmp     y       100000  BM??\x00\x00\x00
download tunn3l_v1s10n and rename it to tunn3l_v1s10n.bmp after confirming that the first two bytes are 42 4d (BM), using a hex editor
copy tunn3l_v1s10n.bmp to an empty sub-directory
set first 7 bytes of tunn3l_v1s10n.bmp to 42 4d 3f 3f 00 00 00, using a hex editor
pass tunn3l_v1s10n.bmp as an argument to scalpel in root user mode
# scalpel tunn3l_v1s10n.bmp
Scalpel version 1.60
Written by Golden G. Richard III, based on Foremost 0.69.

Opening target "/home/shoumik/downloads/tunn3l-v1s10n/bmp_file/tunn3l_v1s10n.bmp"

Image file pass 1/2.
tunn3l_v1s10n.bmp: 100.0% |****************************************************|    2.8 MB    00:00 ETAAllocating work queues...
Work queues allocation complete. Building carve lists...
Carve lists built.  Workload:
bmp with header "\x42\x4d\x3f\x3f\x00\x00\x00" and footer "" --> 1 files
Carving files from image.
Image file pass 2/2.
tunn3l_v1s10n.bmp: 100.0% |****************************************************|    2.8 MB    00:00 ETAProcessing of image file complete. Cleaning up...
Done.
Scalpel is done, files carved = 1, elapsed = 0 seconds.
Before/After Scalpel
42 4d 8e 26 2c 00 00 00 00 00 ba d0 00 00 ba d0 00 00 6e 04 00 00 32 01 00 00 01 00 18 00 00 00 (corrupted bytes)
42 4d 3f 3f 00 00 00 00 00 00 36 00 00 00 28 00 00 00 6e 04 00 00 42 03 00 00 01 00 18 00 00 00 (after scalpel)
Details
first bytes ba d0 were changed to 36 00
second bytes ba d0 were changed to 28 00
bytes 32 01 were changed to 42 03
hex 36 indicates that 54 bytes equals 14-byte-long file header plus 40-byte-long info header
hex 28 indicates a 40 byte-long BMP info header
42 and 03 affect the offsets of the image, as I understand it.
Flag
Thanks to the precise efficiency of scalpel, the picoCTF flag pops at the top of the image:

picoCTF{qu1t3_a_v13w_2020}
```
## Flag
picoCTF{qu1t3_a_v13w_2020}
## What I learned
From solving the “tunn3l v1s10n” challenge, I learned how digital forensics tools like Scalpel can recover or “carve” data from corrupted files by using file signatures and headers.
I understood how important file headers are — especially in formats like BMP, where specific byte values identify the file type and structure.
By using a hex editor to inspect and manually repair the header, I saw how even small changes in a few bytes can make an unreadable file viewable again.

## Challenge 2-Moonwalk
## What I did
```
File type

file moonwalk
# Example: ELF 64-bit LSB executable, x86-64


Strings quick look

strings moonwalk | sed -n '1,200p'
# Look for suspicious messages, hard-coded secrets, function names


Symbols & imports

readelf -s moonwalk | egrep 'main|win|flag|secret|system|exec'
ldd moonwalk


Disassembly / decompilation

Load the binary into Ghidra / IDA or use r2/objdump -d to inspect main and other interesting functions.

Look for:

Format string usage (printf(buf)),

Unsafe functions (strcpy, gets, scanf("%s")),

Crypto routines,

Hard-coded keys, salts, or flags.

(Add a short excerpt from the disassembly that shows the vulnerable code — paste the relevant asm/C snippet.)

Dynamic analysis

Run program locally

./moonwalk
# Observe prompts, behavior, and whether it reads files like flag.txt


Try basic inputs

Send long strings, % sequences, special characters to test filters.

Use valgrind or gdb if the binary crashes.

Debugging

Attach gdb and set breakpoints on functions of interest.

Inspect stack memory for format string exploitation or protected cookie values.

Example (gdb):

gdb -q ./moonwalk
break main
run
# step to vulnerable function

Vulnerability & exploitation

Explain the vulnerability in plain words and why it’s exploitable.

Example templates (choose whichever fits the challenge and edit):

Format string vuln

The program uses printf(user_input) instead of printf("%s", user_input). This lets us use %p, %x, %s, and %n to read stack memory and write arbitrary addresses. We use %s / %p to leak the flag pointer or the flag itself on the stack, or %n to overwrite control data and redirect execution to a function that prints the flag.

Exploit steps (format string example)

Leak stack addresses:

python3 - <<'PY'
from pwn import *
p = process('./moonwalk')
p.recvuntil('> ')
p.sendline('%p %p %p %p %p %p %s')
print(p.recvline())
PY


Parse the leaked pointer / memory and craft payload to read flag:

# Use pwntools fmtstr utilities or manual parsing to create format payload
from pwn import *
payload = b'....'   # crafted
p.sendline(payload)
print(p.recvline())
```
## Flag
picoCTF{beep_boop_im_in_space}


## challenge 3- Trivial Flag Transfer Protocol
## What I did
```
Searching on wikipedia, we see that TFTP is a protocol for transferring files. We open the pcap in wireshark and extract the files with TFTP. There are 5 files. Saving them all and looking at them, there are 2 text files and 3 bmp files.

bmp is a lossless and uncompressed format, so we will likely find the flag there.

A .deb file is an installation file, which 7zip can open, for some reason. Inside, we find archive named data.tar. We can open this with tar -xvf data.tar. This extracts a directory. Searching through it we find a folder usr/share/doc/steghide. The flag is likely encrypted in one of the bmps with the steghide program, which needs a password. We are getting closer.

Instructions.txt and plan are both text files with a bunch of letters that are all capitals. This could potentially a cipher, the first one that came to mind being a caesar cipher. Using a caesar cipher solver, we get these 2 messages from the files:

Instructions.txt: TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN

plan: IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS

Interestingly, the offset for both of the ciphers is +13, which in hindsight should have been trivial because it is also ROT13.

The author of the plan used "the program", likely referring to steghide, with the password DUEDILIGENCE. We now have everything we need to find the flag.

manifold@pwnmachine:~$ steghide extract -sf picture1.bmp -p DUEDILIGENCE
steghide: could not extract any data with that passphrase!
manifold@pwnmachine:~$ steghide extract -sf picture2.bmp -p DUEDILIGENCE
steghide: could not extract any data with that passphrase!
manifold@pwnmachine:~$ steghide extract -sf picture3.bmp -p DUEDILIGENCE
wrote extracted data to "flag.txt".
manifold@pwnmachine:~$ cat flag.txt
picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}
manifold@pwnmachine:~$
Flag: picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}
```
## Flag
picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}
