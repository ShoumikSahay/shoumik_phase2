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
