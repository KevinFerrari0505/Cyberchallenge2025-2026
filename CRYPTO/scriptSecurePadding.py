from pwn import *

HOST = "padding.challs.cyberchallenge.it"
PORT = 9030

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}?!"

flag = ""

while True:

    # numero di A (blocchi da 16)
    k = 15 - (len(flag) % 16)
    prefix = "A" * k

    # quale blocco guardare
    block_index = len(flag) // 16

    r = remote(HOST, PORT)

    r.recvuntil(b"encrypt:")

    r.sendline(prefix.encode())
    line = r.recvline().decode()
    cipher = line.split()[-1]

    ref_block = cipher[block_index*32:(block_index+1)*32]

    r.recvuntil(b"encrypt:")

    found = False

    for c in charset:
        attempt = prefix + flag + c
        print(attempt)
        r.sendline(attempt.encode())
        line = r.recvline().decode()
        cipher = line.split()[-1]

        test_block = cipher[block_index*32:(block_index+1)*32]

        if test_block == ref_block:
            flag += c
            print("FLAG:", flag)
            found = True
            break

        r.recvuntil(b"encrypt:")

    r.close()

    if not found:
        print("Nessun match trovato → probabilmente fine flag")
        break

    if flag.endswith("}"):
        break

print("FINAL FLAG:", flag)
