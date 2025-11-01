# Challenge 1. IQ Test
This challenge we were given with a image with multiple logic gates. We have to take the input and manually count the 12 bit output.

## Solution:
1. First, I noted the input value `x = 30478191278`. Then I converted this decimal number into its binary form using Python
```
>>> print(format(30478191278,"036b"))
011100011000101001000100101010101110
```
This binary string is the input to the logic circuit.(I did 36 bit conversion as there were 36 input bits - from 0 to 35)
2. The challenge involves multiple gates: XOR, XNOR, NAND, AND, OR, NOR, and NOT.
3. The final output binary sequence I derived was `100010011000`. I then formatted this as the flag:`nite{100010011000}`.

## Flag:
```
nite{100010011000}
```

## What did I learn:
- Conversion of decimal numbers to binary.
- Understanding of common logic gates: XOR, XNOR, NAND, AND, OR, NOR, and NOT.







# Challenge 2. I like logic
This challenge involves working with a file that has an unfamiliar extension (.sal) and contains binary data. Ultimately the goal is to uncover hidden or encoded messages within the file that reveal the flag.

## Solution:
1. First, I opened the `.sal` file, but it appeared to contain some binary data that I could not interpret directly.  
2. I searched for the `.sal` extension on Google, and the top result was related to an application called Logic 2, which is used for logic analysis and signal decoding. It immediately clicked as the question name was also the same.

3. I installed Logic 2 on my Linux system, changed its permission to make it executable, and then ran it through the terminal.  
4. It was asking for some connect logic but there was option of `load capture file` - so I clicked on that selected that file and then there was a yellow waveform type of thing like the morse code in citadel.
5. I zoomed it tried to play but nothing was working. 
6. Then I googled some documents like how to extract some hidden texts or values and I found a github repo in which in README section something about - `Analyzers` and `Async Serial` was written to read some data from the file.
7. I clicked on the Analyzer tab in Logic 2, selected the Async Serial analyzer and it had various settings in it. 
    <img width="1920" height="983" alt="image (4)" src="https://github.com/user-attachments/assets/a96f458a-1d07-4619-b772-f77b0aa52e66" />

8. I was really confused so I selected the channel0 and default settings but nothing worked. Then I did repeatedly but for 3 channel it worked and some texts were written above the waveform.
    <img width="1920" height="983" alt="image (5)" src="https://github.com/user-attachments/assets/bdf007d0-338d-49ba-b2bf-0ff8429726c6" />

9. Then I was not able to read the whole text but after some trials I found the button to see whole text I copied in a normal text file.
    ```
    on't think he makes any claims of
    that kind.  But I do believe he has got something new."

    ..............(some text)..........
    FCSC{b1dee4eeadf6c4e60aeb142b0b486344e64b12b40d1046de95c89ba5e23a9925}
    ..............(some text)..........

    It was a bird's-eye view of creation, as interpreted by science, which,
    in language always clear and sometimes picturesque, he unfolded before
    us.  He told us of t
    ```
    <img width="978" height="939" alt="image (6)" src="https://github.com/user-attachments/assets/bc0dbe0e-ef89-4585-9767-d529a2ff0b0a" />

10. And there was a flag type of text which was the flag.

## Flag:
```
FCSC{b1dee4eeadf6c4e60aeb142b0b486344e64b12b40d1046de95c89ba5e23a9925}
```  

## What did I learn:
- Recognizing file types based on extensions and content.  
- Using external tools (Logic 2) for signal analysis and decoding.  
- Loading and analyzing binary or waveform data within a specialized application.  



# Challenge 3. Bare Metal Alchemist
This challenge involves analyzing a binary file that is encrypted. The goal is to identify the hidden flag within the binary. It involves some trial and error as well as pattern matching, to find the correct key and decode the flag.

## Solution:
1. First, I tried using `binwalk` on the binary file to see if there were any embedded compressed or filesystem data but nothing useful came up. Next, I used the `strings` command to look for any readable text, but again no flag was visible.
2. I uploaded the binary to an online decompiler that I used previously during Citadel CTF, It has decompilers such as Ghidra, Reko, BinaryNinja, and RecStudio. I  i uploaded that file in that and began to read all the codes.
    <img width="1919" height="900" alt="image (7)" src="https://github.com/user-attachments/assets/693eba53-6648-4bc3-b86f-ed71923340e9" />

3. After I went through reading all the codes one by one and I noticed in ghidra that some random random byte constants are used. I saw code snippets like `bVar5 = *(byte *)(uint3)uVar2;` and conditional checks involving byte values.
    ```
    Var5 = *(byte *)(uint3)uVar2;
    if ((bVar5 == 0) || (bVar5 == 0xa5)) goto LAB_code_000131;
    bVar4 = DAT_mem_0009;
    if (((bVar4 ^ bVar4 * '\x02') & 4) == 0) break;
    bVar5 = (bVar5 ^ 0xa5) - 0x30;
    bVar4 = 0;
    if (bVar5 < 0x4e) {
    bVar4 = *(byte *)CONCAT11(1,bVar5);
    }
    ```
4. I opened Reko and observed several global byte variables with assigned values.
    ```
    byte g_b006E = 222; // 006E
    byte g_b007A = 0x96; // 007A
    byte g_b0080 = 0xC9; // 0080
    byte g_b0081 = 0x96; // 0081
    byte g_b00B0 = 0x0D; // 00B0
    byte g_b00B1 = 0x92; // 00B1
    byte g_b00C1 = 0x92; // 00C1
    ```
    There were many constants so I began to search why they are being used and I got to know something about - `encryption keys` (for XOR, AES, etc.), so first I went for What is XOR using a youtube video.
5. I works something like -   
`decrypted_byte = encrypted_byte ^ key_byte;`  
I tried for 1 byte XOR decryption and to automate this, I wrote a Python script that reads the binary data (`firmware.elf`) and attempts XOR decryption with all possible byte values from 1 to 255.
    ```python
    import re, string

    data = open("firmware.elf", "rb").read()
    pat = re.compile(rb"[A-Za-z0-9_]{1,20}\{[A-Za-z0-9_\-\+\=\/\\\.\s]{4,200}\}")
    printable = set(string.printable)

    for k in range(1,256):
        dec = bytes(b ^ k for b in data)
        m = pat.search(dec)
        if m:
            s = m.group().decode(errors="ignore").strip()
            if "{" in s and "}" in s and all(ch in printable for ch in s):
                print("key:", k, s)

    ```
6. The script uses a regex pattern to search for strings resembling typical flag formats, such as `SOMETHING{...}`. For each key, it XORs all bytes and searches for a match. If a match is found, it prints out the key and the decoded string.
7. Running the script, It gave multiple flag strings, but `TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}` was the flag with key 165.
    ```

    key: 9 mfVjelh{VkzzVz}
    key: 11 T{ydlyjf
    TT}
    key: 19 LL{vrcLv}
    key: 24 GG{lwjkG}
    key: 26 lh5{lh/5vsx}
    key: 30 Aqh{lxrqiA}
    key: 46 ojc{v.ojm.ojm}
    key: 52 4kkqqdf{ykfqs}
    key: 56 yt8{tshj8kj}
    key: 57 9mnxtk9mn{k9mnzk9mnjk9mn}
    key: 66 HBB{vBALxIyI
    Q}
    key: 68 W{HFNDD}
    key: 71 TxKEMGG{sGDI}
    key: 107 mzjyjhcpcNcxnkkkjzk{mzjyjhcpcNcxnkkk}
    key: 109 hmmm{mmmom}
    key: 118 vv{BvuxL}
    key: 121 yy{yyyyy}
    key: 122 zzzzzzzzxuzzz{rymzzzx}
    key: 165 TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}
    ```



## Flag:
```
TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}
```

## What did I learn:
- Analyzing binary files with tools like Ghidra, Reko, and online decompilers.
- Recognizing common techniques such as XOR encryption/decryption.
- Using regex in Python to match potential flag formats(I searched google for that).
- Automating decryption attempts with XOR keys.

