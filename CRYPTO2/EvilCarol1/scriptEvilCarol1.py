from Crypto.Util.number import long_to_bytes
import hashlib
from Crypto.Cipher import AES
from pwn import remote

io = remote("carol.challs.cyberchallenge.it", 9045)

# Leggi i parametri originali
io.recvuntil(b"p: ");          p    = int(io.recvline())
io.recvuntil(b"pubA: ");       pubA = int(io.recvline())
io.recvuntil(b"pubB: ");       _    = io.recvline()  # non serve
io.recvuntil(b"Encrypted flag: "); ct_flag = io.recvline().strip().decode()

# Invia i nostri parametri
# g = pubA  →  pubB = pubA^privB mod p  =  shared_secret!
io.recvuntil(b"Enter your prime: ");     io.sendline(str(p).encode())
io.recvuntil(b"Enter the generator: "); io.sendline(str(pubA).encode())  # <-- il trucco
io.recvuntil(b"Enter your public value: "); io.sendline(b"1")  # qualsiasi
io.recvuntil(b"Enter your message: ");   io.sendline(b"hello")

io.recvuntil(b"pubB: ")
shared_secret = int(io.recvline())  # questo è già il shared secret!

# Decifra la flag
key    = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag   = cipher.decrypt(bytes.fromhex(ct_flag))
print(f"[*] FLAG: {flag}")
