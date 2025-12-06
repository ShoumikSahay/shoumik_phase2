

# Challenge - Residue refinery


## Description
We are provided with a script `chall.py` that implements a custom number class `Num`. The script encrypts a flag using a randomly generated 2-byte key (`ks`). 

The encryption logic involves:
1.  Splitting the flag into 2-byte chunks.
2.  Multiplying each chunk by the key `ks`.
3.  Operations are performed in a finite field modulo $257$.

We are given the encrypted output (ciphertext) and the first two bytes of the plaintext (derived from the `flag[:2]` hint in the output).

## Analysis

### 1. The Field
The `Num` class performs arithmetic in the ring $\mathbb{Z}_{257}[x] / (x^2 - 3)$.
- **Modulus:** $P = 257$
- **Polynomial Reduction:** $x^2 \equiv 3 \pmod{257}$

### 2. The Operation
Multiplication of two numbers $A = a_0 + a_1x$ and $B = b_0 + b_1x$ is defined as:
$$(a_0 + a_1x)(b_0 + b_1x) = (a_0b_0 + 3a_1b_1) + (a_0b_1 + a_1b_0)x$$

This is essentially matrix multiplication. If we treat the Key $K$ as a linear transformation applied to the Message $M$, we get:
$$C = K \times M$$

### 3. The "Gotcha"
The `to_bytes` method reverses the array before outputting:
```python
def to_bytes(self):
    return bytes(self.n.tolist())[::-1]
```
## Solution strategy
### 1.
```
Recover the Key: We know the first 2 bytes of the plaintext (1m) and their corresponding ciphertext (0x9813).
We set up a system of linear equations: $C_0 = K \cdot M_0$.We solve for $K$ by multiplying by the modular inverse of $M_0$: $K = C_0 \cdot M_0^{-1}$.
```
### 2.
```
Decrypt: Once $K$ is known, we compute its inverse matrix $K^{-1}$.
```
### 3.
```
Apply: We multiply every subsequent ciphertext block by $K^{-1}$ to retrieve the flag.
```
## Solver Code
```
# Constants from the challenge
P = 257
CT_HEX = "9813d3838178abd17836f3e2e752a99d5cd3fba291205f90c1d0a78b6eca"
KNOWN_PT_HEX = "316d" # Corresponds to '1m'

# Parse inputs
ct_bytes = bytes.fromhex(CT_HEX)
known_pt = bytes.fromhex(KNOWN_PT_HEX)

# --- Step 1: Recover the Key (ks) ---
# Note: due to to_bytes()[::-1], byte 0 is coeff 1, byte 1 is coeff 0
m0 = known_pt[0] 
m1 = known_pt[1] 
c1 = ct_bytes[0] 
c0 = ct_bytes[1] 

# Solve linear system to find Key (k0, k1)
# Matrix M determinant
det_M = (m0 * m0 - 3 * m1 * m1) % P
det_M_inv = pow(det_M, -1, P)

# Inverse Matrix multiplication
k0 = (det_M_inv * (m0 * c0 - 3 * m1 * c1)) % P
k1 = (det_M_inv * (-m1 * c0 + m0 * c1)) % P

print(f"[*] Key Recovered: k0={k0}, k1={k1}")

# --- Step 2: Decrypt the Ciphertext ---
flag_content = b""

# Calculate Inverse of Key Matrix
det_K = (k0 * k0 - 3 * k1 * k1) % P
det_K_inv = pow(det_K, -1, P)

for i in range(0, len(ct_bytes), 2):
    curr_c1 = ct_bytes[i]   
    curr_c0 = ct_bytes[i+1]
    
    # Apply K^-1 to Ciphertext
    p0 = (det_K_inv * (k0 * curr_c0 - 3 * k1 * curr_c1)) % P
    p1 = (det_K_inv * (-k1 * curr_c0 + k0 * curr_c1)) % P
    
    flag_content += bytes([p0, p1])

print(f"[*] Full Flag: nite{{{flag_content.decode()}}}")
```
## OUTPUT
```
[*] Key Recovered: k0=60, k1=6
[*] Decrypted content: b'1mp0r7_m0dul3?_1_4M_7h3_m0dul3'
[*] Full Flag: nite{1mp0r7_m0dul3?_1_4M_7h3_m0dul3}
```

## FLAG
```
nite{1mp0r7_m0dul3?_1_4M_7h3_m0dul3}
```
# Challenge - All Signs Align
## Challenge Description
```
A custom encryption scheme based on quadratic residues modulo a large prime. The flag is encoded bit-by-bit using the quadratic residuosity of numbers.
```
## Key Observations:
```
p is a large prime (likely ≡ 3 mod 4)

get_x() returns a quadratic residue (QR) modulo p

get_y() returns -x mod p, which is a quadratic non-residue (QNR) when p ≡ 3 mod 4

A fixed random QR a multiplies each output

Each bit of the flag determines whether to use x (QR) or y (QNR)

```
## Cryptographic Analysis
```
Mathematical Properties
For prime p ≡ 3 mod 4:

Euler's criterion: x is QR if x^((p-1)/2) ≡ 1 mod p

-1 is a QNR when p ≡ 3 mod 4

Multiplication rules:

QR × QR = QR

QR × QNR = QNR

Encoding Scheme
Given a fixed QR a:

If flag bit = 0: output = a × x (QR × QR = QR)

If flag bit = 1: output = a × y (QR × QNR = QNR)

Thus, each number in out.txt reveals one bit of the flag through its quadratic residuosity.
```
## Attack Methodology
```
Step 1: Verify Prime Properties
python
p = 9129026491768303016811207218323770273047638648509577266210613478726929333106121387323539916009107476349319902011390210650434835260358014251332047605739279
print(f"p mod 4 = {p % 4}")  # Output: 3
print(f"p is prime: {isPrime(p)}")  # Output: True
Step 2: Determine Quadratic Residuosity
Using Euler's criterion for each number n in out.txt:

Compute r = pow(n, (p-1)//2, p)

If r == 1: n is QR → flag bit = ?

If r == p-1: n is QNR → flag bit = ?

Step 3: Bit Mapping Discovery
Initial assumption (from code reading): QR → '0', QNR → '1'
However, this produced garbled output.

After testing both mappings:

QR → '0', QNR → '1': Garbage

QR → '1', QNR → '0': Meaningful text

Step 4: Bit Alignment
The binary string had 263 bits (263 % 8 = 7), requiring bit offset correction:

Offset 0-6: Garbage

Offset 7: Readable flag text

Solution Script
python
import ast

p = 9129026491768303016811207218323770273047638648509577266210613478726929333106121387323539916009107476349319902011390210650434835260358014251332047605739279

with open('out.txt', 'r') as f:
    numbers = ast.literal_eval(f.read())

exponent = (p - 1) // 2

# Correct mapping: QR → '1', QNR → '0'
bits = ''.join('1' if pow(n, exponent, p) == 1 else '0' for n in numbers)

# Apply offset 7 for proper byte alignment
bits = bits[7:]
bits = bits[:-(len(bits) % 8)]  # Trim to multiple of 8

# Convert to ASCII
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(f"Flag: {flag}")
```
## FLAG
```
ite{r3s1du35_f4ll1ng_1nt0_pl4c3}
```
## Key Insights
```
Bit Mapping Reversal: The intuitive mapping from the source code was reversed in practice

Bit Alignment: 263 bits required a 7-bit offset for proper ASCII decoding

Mathematical Foundation: Understanding quadratic residues modulo primes ≡ 3 mod 4 was crucial

Euler's Criterion: Essential tool for determining quadratic residuosity
```
# Challenge - Quixorte
## Challenge Description
```
A custom encryption algorithm combining bit rotation and XOR operations was used to encrypt a PNG image. The goal is to recover the original image containing the flag.
```
## Key Observations
```
Two-stage encryption:

Stage 1: Each byte is rotated right by its position index

Stage 2: Sliding XOR with an 8-byte key

Key characteristics: 8 random bytes, reused throughout encryption

Known plaintext: PNG files have fixed header bytes

```
## Cryptographic Analysis
```\Encryption Process
For each byte at position i:

intermediate[i] = rotate(plain[i], i) where rotate performs right rotation

cipher[i] = intermediate[i] ⊕ key[0] ⊕ key[1] ⊕ ... ⊕ key[j] where j = min(i, 7) for first 8 bytes

Mathematical Representation
Let:

R(i) = rotate(plain[i], i) (right rotation by i bits)

K(j) = ⊕_{k=0}^{j} key[k] (cumulative XOR of key bytes)

For first 8 bytes:

text
cipher[0] = R(0) ⊕ K(0)
cipher[1] = R(1) ⊕ K(1)
cipher[2] = R(2) ⊕ K(2)
...
cipher[7] = R(7) ⊕ K(7)
For bytes ≥ 8:

text
cipher[i] = R(i) ⊕ key[i%8] ⊕ key[(i+1)%8] ⊕ ... ⊕ key[7]
```
## Attack Methodology
```
Step 1: Known Plaintext Recovery
PNG files always begin with: 89 50 4E 47 0D 0A 1A 0A (hex)

Step 2: Key Recovery
Using the PNG header and the encryption equations:

Compute R(i) = rotate(png_header[i], i) for i = 0..7

Compute cumulative XOR values: K(i) = cipher[i] ⊕ R(i)

Extract individual key bytes:

key[0] = K(0)

key[i] = K(i) ⊕ K(i-1) for i = 1..7

Step 3: Decryption Algorithm
python
def decrypt(cipher, key):
    dec = bytearray(cipher)
    
    # Reverse XOR (same as encryption due to XOR properties)
    for i in range(len(dec) - len(key) + 1):
        for j in range(len(key)):
            dec[i+j] ^= key[j]
    
    # Reverse rotation (left rotate to undo right rotate)
    for i in range(len(dec)):
        dec[i] = ((dec[i] << (i % 8)) | (dec[i] >> (8 - (i % 8)))) & 0xFF
    
    return bytes(dec)
Solution Script
python
def rotate(b, i):
    return ((b >> (i % 8)) | (b << (8 - (i % 8)))) & 0xFF

def decrypt(enc, key):
    dec = bytearray(enc)
    
    # Reverse sliding XOR
    for i in range(len(dec) - len(key) + 1):
        for j in range(len(key)):
            dec[i+j] ^= key[j]
    
    # Reverse rotation (left rotate)
    for i in range(len(dec)):
        dec[i] = ((dec[i] << (i % 8)) | (dec[i] >> (8 - (i % 8)))) & 0xFF
    
    return bytes(dec)

# Known PNG header
png_magic = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

# Read encrypted file
with open('quote.png.enc', 'rb') as f:
    enc = f.read()

# Recover key using known plaintext
R = [rotate(png_magic[i], i) for i in range(8)]
K = [enc[i] ^ R[i] for i in range(8)]

key = bytearray(8)
key[0] = K[0]
for i in range(1, 8):
    key[i] = K[i] ^ K[i-1]

print(f"Recovered key: {key.hex()}")

# Decrypt entire file
decrypted = decrypt(enc, key)

# Save and verify
with open('quote.png', 'wb') as f:
    f.write(decrypted)

print("Decryption successful. Image saved as quote.png")
```
## Execution Results
```
File size: 153026 bytes
Recovered key: ec95e0220a3d5ab7
✓ PNG header verified!
Saved as quote.png
```
## FLAG
```
nite{t0_b3_X0R_n0t_t0_b3333}
```
# Challenge - Willy's Chocolate Experience
## Challenge Description
```
A custom mathematical function based on Willy Wonka's "imagination lab" encodes a golden ticket (the flag). The challenge requires recovering the ticket from two output values.
```
## Key Observations
```
Custom function: imagination_lab(m) = 13^m + 37^m mod p

Large prime modulus: p (1024-bit prime)

Output: Last two elements of sequence: [imagination_lab(ticket-1), imagination_lab(ticket)]

Goal: Recover ticket = bytes_to_long(b"nite{...}")
```
## Mathematical Analysis
```
Sequence Properties
Let s(m) = 13^m + 37^m mod p. This sequence satisfies a linear recurrence:


s(m+2) = (13+37) * s(m+1) - 13*37 * s(m) mod p
       = 50 * s(m+1) - 481 * s(m) mod p
Given Values
We have:


a = s(t-1) = 13^(t-1) + 37^(t-1) mod p
b = s(t)   = 13^t + 37^t mod p
Solving for Individual Terms
Let:

X = 13^(t-1) mod p

Y = 37^(t-1) mod p

Then:


a = X + Y mod p
b = 13X + 37Y mod p
This is a system of linear equations. Solving:


Y = a - X mod p
b = 13X + 37(a - X) = 37a - 24X mod p
24X = 37a - b mod p
X = (37a - b) * 24^(-1) mod p
Y = a - X mod p
```
## Solution Implementation
```
Step 1: Compute X and Y
python
p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807

a = 124499652441066069321544812234595327614165778598236394255418354986873240978090206863399216810942232360879573073405796848165530765886142184827326462551698684564407582751560255175
b = 208271276785711416565270003674719254652567820785459096303084135643866107254120926647956533028404502637100461134874329585833364948354858925270600245218260166855547105655294503224

inv24 = inverse_mod(24, p)
X = ((37 * a - b) * inv24) % p  # = 13^(t-1) mod p
Y = (a - X) % p                 # = 37^(t-1) mod p
Step 2: Solve Discrete Logarithm
We need to solve:

text
13^(t-1) ≡ X mod p
This is a discrete logarithm problem. The modulus p is specially chosen such that p-1 has small prime factors (smooth), making the Pohlig-Hellman algorithm efficient.

Step 3: SageMath Solution
sage
# Define finite field
F = GF(p)
g = F(13)  # Base
h = F(X)   # Target

# SageMath solves discrete log efficiently using Pohlig-Hellman
t_minus_1 = discrete_log(h, g)
t = t_minus_1 + 1

# Convert to flag
flag = int(t).to_bytes((t.bit_length() + 7) // 8, 'big')
print(f"Flag: {flag}")
```
## Execution results
```
Solving discrete log...
t-1 = 762035150520137567051383230813374869523369672000904743873872089989543804
t = 762035150520137567051383230813374869523369672000904743875
Flag: b'nite{g0ld3n_t1ck3t_t0_gl4sg0w}'
Flag as string: nite{g0ld3n_t1ck3t_t0_gl4sg0w}
```
## Flag
```
nite{g0ld3n_t1ck3t_t0_gl4sg0w}
```


