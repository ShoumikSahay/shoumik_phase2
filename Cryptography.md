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
