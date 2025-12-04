

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
