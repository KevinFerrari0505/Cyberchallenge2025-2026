from pwn import *
from Crypto.Util.number import long_to_bytes
from math import gcd

io = remote('oracle.challs.cyberchallenge.it', 9042)

io.recvuntil(b'Encrypted flag: ')
C = int(io.recvline().strip())
print(f"[+] C = {C}")

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
    line = io.recvline()
    if b'illegal' in line:
        return None
    io.recvuntil(b'Decrypted: ')
    # la riga con il numero è la prossima
    return int(io.recvline().strip())

# ── Step 1: Modulus Recovery (senza usare used!) ──────────────────────
# NON usiamo encrypt_val per non aggiungere valori a used!
# Usiamo due chiamate encrypt solo per N recovery — ma questo aggiunge a used...
# Alternativa: usare decrypt per inferire N

# Trick: D(C * 2^e) localmente richiede N
# Usiamo encrypt 2 e 3 (vengono aggiunti a used, ma non importa se flag non è multiplo di 2 o 3)
print("[*] Recovering N...")
enc2 = encrypt_val(2)   # used = [flag, 2]
enc3 = encrypt_val(3)   # used = [flag, 2, 3]

n = gcd(pow(2, e) - enc2, pow(3, e) - enc3)
assert n.bit_length() == 1024, f"N sbagliato: {n.bit_length()} bit"
print(f"[+] N = {n}")

# ── Step 2: LSB Oracle / Binary Search ───────────────────────────────
# Calcola 2^e mod n LOCALMENTE — non chiede al server, non modifica used!
# Il risultato di decrypt sarà 2*flag, 4*flag, ... mod n
# Il check è: risultato % flag == 0 → SEMPRE bloccato!

# QUINDI: non possiamo usare il metodo omomorfico diretto.
# Usiamo la binary search sull'LSB:
# decrypt(2^e * C) = 2*flag mod n
# se è dispari → 2*flag > n → flag > n/2
# se è pari   → 2*flag < n → flag < n/2

lo = 0
hi = n
c_curr = C

print("[*] LSB binary search...")
for i in range(1024):
    # Calcola 2^e mod n localmente e moltiplica per c_curr
    factor = pow(2, e, n)
    c_curr = (c_curr * factor) % n
    
    m = decrypt_val(c_curr)
    
    if m is None:
        print(f"[!] Bloccato al bit {i}")
        break
    
    mid = (lo + hi) // 2
    
    if m % 2 == 1:  # dispari → wrap around → flag nella metà alta
        lo = mid
    else:           # pari → no wrap → flag nella metà bassa
        hi = mid
    
    print(f"[*] Bit {i+1}/1024 | lo={lo.bit_length()} hi={hi.bit_length()} bit", end='\r')

flag = long_to_bytes(hi)
print(f"\n[+] Flag: {flag.decode()}")

io.close()
