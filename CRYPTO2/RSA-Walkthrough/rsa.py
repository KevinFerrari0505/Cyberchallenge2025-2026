from pwn import *
from Crypto.Util.number import inverse

conn = remote("rsa.challs.cyberchallenge.it", 9040)

#LEVEL 1
conn.recvuntil(b"p = ")
p = int(conn.recvline())

conn.recvuntil(b"q = ")
q = int(conn.recvline())

n = p * q

conn.sendlineafter(b"n = ?", str(n).encode())

#LEVEL 2
conn.recvuntil(b"message = ")
msg = conn.recvline().strip()

m = int.from_bytes(msg, byteorder="big")

conn.sendlineafter(b"m = ?", str(m).encode())

#LEVEL 3
conn.recvuntil(b"p = ")
p = int(conn.recvline())

conn.recvuntil(b"q = ")
q = int(conn.recvline())

n = p * q

conn.recvuntil(b"m = ")
m = int(conn.recvline())

conn.recvuntil(b"e = ")
e = int(conn.recvline())

c = pow(m, e, n)
conn.sendlineafter(b"c = ?", str(c).encode())

#LEVEL 4
conn.recvuntil(b"p = ")
p = int(conn.recvline())

conn.recvuntil(b"q = ")
q = int(conn.recvline())

conn.recvuntil(b"e = ")
e = int(conn.recvline())

phi = (p - 1) * (q - 1)
conn.sendlineafter(b"tot(n) = ?", str(phi).encode())

d = inverse(e, phi)
conn.sendlineafter(b"d = ?", str(d).encode())

#LEVEL 5
conn.recvuntil(b"p = ")
p = int(conn.recvline())

conn.recvuntil(b"q = ")
q = int(conn.recvline())

conn.recvuntil(b"e = ")
e = int(conn.recvline())

conn.recvuntil(b"c = ")
c = int(conn.recvline())


n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
conn.sendlineafter(b"m = ?", str(m).encode())

conn.interactive()
