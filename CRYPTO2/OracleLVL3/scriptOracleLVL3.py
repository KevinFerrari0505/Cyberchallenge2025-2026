from pwn import *
from Crypto.Util.number import long_to_bytes
from math import gcd
import random

io = remote('oracle.challs.cyberchallenge.it', 9043)

io.recvuntil(b'Encrypted flag: ')
C = int(io.recvline().strip())
print(f"[+] flag_encrypted = {C}")

e = 65537

def encrypt_val(val):
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'Plaintext > ')
    io.sendline(str(val).encode())
    io.recvuntil(b'Encrypted: ')
    return int(io.recvline().strip())

def decrypt_val(val):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'Ciphertext > ')
    io.sendline(str(val).encode())
    io.recvuntil(b'Decrypted: ')
    return int(io.recvline().strip())

# ── Step 1: Modulus Recovery ──────────────────────────────────────────
print("[*] Recovering N...")

x, y = 2, 3
enc_x = encrypt_val(x)
enc_y = encrypt_val(y)

x_e = pow(x, e)   # 2^65537 esatto
y_e = pow(y, e)   # 3^65537 esatto

n = gcd(x_e - enc_x, y_e - enc_y)

print(f"[+] N = {n}")
print(f"[+] N bits = {n.bit_length()}")

# ── Step 2: Homomorphic Property  ───────────────────────────
# Scelgo x=2, calcolo x^e mod n
x = 2
x_e = pow(x, e, n) #cifrato

# Manda x^e * C al server
C_blind = (x_e * C) 
m_blind = decrypt_val(C_blind)   # = x * flag mod n

# Recupero flag dividendo per x
# flag = m_blind / x mod n  =  m_blind * x^(-1) mod n
flag_int = (m_blind * pow(x, -1, n)) % n
print(f"[+] Flag: {long_to_bytes(flag_int).decode()}")

io.close()
