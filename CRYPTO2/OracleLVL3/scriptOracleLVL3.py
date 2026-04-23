from pwn import *
from Crypto.Util.number import long_to_bytes, GCD, size
from decimal import getcontext

conn = remote("oracle.challs.cyberchallenge.it", 9043)

def getFlag():
    msg = conn.recvuntil(b"Encrypted flag: ")
    return int(conn.recvline())
def getToInputLine():
    msg = conn.recvuntil(b'> ')
    return msg
def encrypt(msg):
    getToInputLine()
    conn.sendline(b"1")
    getToInputLine()
    conn.sendline(msg.encode())
    conn.recvuntil(b"\nEncrypted: ")
    return int(conn.recvline())
def decrypt(msg):
    getToInputLine()
    conn.sendline(b"2")
    getToInputLine()
    conn.sendline(msg.encode())
    conn.recvuntil(b"\nDecrypted: ")
    return int(conn.recvline())
def findClearFlag():
    flag = getFlag()
    e = 65537
    numbers = [191, 197]
    diffs = []
    for number in numbers:
        cipher = encrypt(str(number))
        diffs.append(number**e - cipher)
    n = GCD(diffs[0], diffs[1])
    print(size(n))
    flag = decrypt(str(-flag))
    flag = (-1 * (flag)) % n
    return long_to_bytes(flag)

print(findClearFlag())
