# Module-Cryptography
## Challenge 1- MINI RSA
## What I did
```
Although we cannot run a cube root attack, we do realize that e is only 3 and m^e is barely larger than n we could see brute force the plaintext by just trying to add the public modulus.

RSA encryption uses : c = m^e mod n
RSA decryption could use: p = (c+xn)^(1/e)
Here, x is probably not so large so we can test that theory out. Initially, I used the decimal python module but the results were not accurate enough thus not giving me a flag. I move on to use a sage math kernel which handles numbers way better than python and it gave me the flag with ease.
```
## Flag
picoCTF{e_sh0u1d_b3_lArg3r_85d643d5}



## Challenge 2- Custom Encryption
## What I did
```
a = 95 b = 21 cipher is: [237915, 1850450, 1850450, 158610, 2458455, 2273410, 1744710, 1744710, 1797580, 1110270, 0, 2194105, 555135, 132175, 1797580, 0, 581570, 2273410, 26435, 1638970, 634440, 713745, 158610, 158610, 449395, 158610, 687310, 1348185, 845920, 1295315, 687310, 185045, 317220, 449395]

Custom encrytion.py
from random import randint  
import sys  
  
  
def generator(g, x, p):  
	return pow(g, x) % p  
  
  
def encrypt(plaintext, key):
	cipher = []  
	for char in plaintext:  
		cipher.append(((ord(char) * key*311)))  
	return cipher  
  
  
def is_prime(p):  
	v = 0  
	for i in range(2, p + 1):  
		if p % i == 0:  
			v = v + 1  
	if v > 1:  
		return False  
	else:  
		return True  
  
  
def dynamic_xor_encrypt(plaintext, text_key):  
	cipher_text = ""  
	key_length = len(text_key)  
	for i, char in enumerate(plaintext[::-1]):  
		key_char = text_key[i % key_length]  
		encrypted_char = chr(ord(char) ^ ord(key_char))  
		cipher_text += encrypted_char  
	return cipher_text  
  
  
def test(plain_text, text_key):  
	p = 97  
	g = 31  
	if not is_prime(p) and not is_prime(g):  
		print("Enter prime numbers")  
		return  
	a = randint(p-10, p)  
	b = randint(g-10, g)  
	print(f"a = {a}")  
	print(f"b = {b}")  
	u = generator(g, a, p)  
	v = generator(g, b, p)  
	key = generator(v, a, p)  
	b_key = generator(u, b, p)  
	shared_key = None  
	if key == b_key:  
		shared_key = key  
	else:  
		print("Invalid key")  
		return  
	semi_cipher = dynamic_xor_encrypt(plain_text, text_key)  
	cipher = encrypt(semi_cipher, shared_key)  
	print(f'cipher is: {cipher}')  
  
  
if __name__ == "__main__":  
	message = sys.argv[1]  
	test(message, "trudeau")

--------------------------------------------------------

from custom_encryption import is_prime, generator
 
 
def leak_shared_key(a, b):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
 
    return shared_key
 
 
def decrypt(ciphertext, key):
    semi_ciphertext = []
    for num in ciphertext:
        semi_ciphertext.append(chr(round(num / (key * 311))))
    return "".join(semi_ciphertext)
 
 
def dynamic_xor_decrypt(semi_ciphertext, text_key):
    plaintext = ""
    key_length = len(text_key)
    for i, char in enumerate(semi_ciphertext):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plaintext += decrypted_char
    return plaintext[::-1]
 
 
if __name__ == "__main__":
    # 0. Take relevant values from `enc_flag` and `custom_encryption.py`
    a = 95
    b = 21
    ciphertext_arr = [
        237915, 1850450, 1850450, 158610, 2458455, 2273410, 1744710, 1744710, 1797580, 1110270, 0, 2194105, 555135, 132175, 1797580, 0, 581570, 2273410, 26435, 1638970, 634440, 713745, 158610, 158610, 449395, 158610, 687310, 1348185, 845920, 1295315, 687310, 185045, 317220, 449395
    ]
    text_key = "trudeau"
 
    # 1. Get the shared key used in `test`
    shared_key = leak_shared_key(a, b)
 
    # 2. Invert the `encrypt` operation
    semi_ciphertext = decrypt(ciphertext_arr, shared_key)
 
    # 3. Invert the `dynamic_xor_encrypt` operation
    plaintext = dynamic_xor_decrypt(semi_ciphertext, text_key)
 
    # 4. Output the flag
    print(plaintext)

```
## Flag
picoCTF{custom_d2cr0pt6d_66778b34}

## Challenge 3- RSA Oracle
## What I did
```
****************************THE ORACLE****************************
******************************************************************

what should we do for you?
E --> encrypt D --> decrypt.
E
enter text to encrypt (encoded length must be less than keysize): a

encoded cleartxt as Hex m: 61

ciphertext (m ^ e mod n) 1894792376935242028465556366618011019548511575881945413668351305441716829547731248120542989065588556431978903597240454296152579184569578379625520200356186

what should we do for you?
E --> encrypt D --> decrypt.
D
Enter text to decrypt: 309735726585317108676257714648578801421395651738025219563295728630193928274008235897503046918439886052744534893787983156475536146366758154420391810256611847120173988337373791004871904106220076227501246689936260227532178819705625123684123321350185635500398774070100065478919921540000252731735761585821431042
decrypted ciphertext as hex (c ^ d mod n): 28da4c293cc41d8e83fefd61e0185ce1b5c43a61cc6068c5fb8474f4e28f0371c8cc854c4bb7247c24fa2aef5095c0bbe5a3d13cd259b006c24c88840c17dd73
decrypted ciphertext: (raw bytes printed)

what should we do for you?
E --> encrypt D --> decrypt.
python
Copy code
Phase 1: Get password
c = 1634668422544022562287275254811184478161245548888973650857381112077711852144181630709254123963471597994127621183174673720047559236204808750789430675058597

Enter message (m1): a
Have the oracle encrypt this message (m1): a

Enter ciphertext from oracle (c1 = E(m1)): 1894792376935242028465556366618011019548511575881945413668351305441716829547731248120542989065588556431978903597240454296152579184569578379625520200356186

Have the oracle decrypt this message (c2 = c * c1): 309735726585317108676257714648578801421395651738025219563295728630193928274008235897503046918439886052744534893787983156475536146366758154420391810256611847120173988337373791004871904106220076227501246689936260227532178819705625123684123321350185635500398774070100065478919921540000252731735761585821431042

Enter decrypted ciphertext as HEX (m2 = D(c2)): 28da4c293cc41d8e83fefd61e0185ce1b5c43a61cc6068c5fb8474f4e28f0371c8cc854c4bb7247c24fa2aef5095c0bbe5a3d13cd259b006c24c88840c17dd73

Password (m = m2 / m1) — binary password (hex):
6bd147aecfe0a2757c07e3fa648a31d50205e1568f826654684b1a46f4474b11e7b77a3049255318223fc867c234219b7088c1496d217c1c6513e1b0f30cd6

To create pass.bin from that hex:
printf "6bd147aecfe0a2757c07e3fa648a31d50205e1568f826654684b1a46f4474b11e7b77a3049255318223fc867c234219b7088c1496d217c1c6513e1b0f30cd6" | xxd -r -p > pass.bin

-------------------------------------------------
Phase 2: Decrypt secret.enc
# then run (replace path if needed):
openssl enc -aes-256-cbc -d -in /Users/shoumiksahay/Downloads/secret.enc -pass file:pass.bin -pbkdf2 -out decrypted.txt
# If pbkdf2 fails, try:
openssl enc -aes-256-cbc -d -in /Users/shoumiksahay/Downloads/secret.enc -pass file:pass.bin -out decrypted.txt

Password (m = m2 / m1): 2113c
picoCTF{su@(3ss_(r@ck1ng_r3@_3319c817}
```
## Flag
picoCTF{su@(3ss_(r@ck1ng_r3@_2113c817}
