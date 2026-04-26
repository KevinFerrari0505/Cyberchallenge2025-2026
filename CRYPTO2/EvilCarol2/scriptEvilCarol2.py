from sympy.ntheory import discrete_log
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
from pwn import remote

P_WEAK = 31472888211913033014656581334286071299271841826488409328264150393281678575155696926737760397712077519004292599775363186110806852950522366739787254121695975639720373192930755254495570048081990735612116875065053260972005827841107574749091623368902041118383201780660880501874583807806273560269977529880250557004858748112628286285953196385745751298472214053677326548583602748511951589775899056754902665135327876223927054050320406291083246556433727453777638877463119925152625645783832775321478764177977574451694185984645322935549751349097740839155383275499417799181041562209847473166247030133737572431727525639894562727941

io = remote("carol.challs.cyberchallenge.it", 9046)

# Leggi i parametri di Alice/Bob
io.recvuntil(b"p: ");              p_orig  = int(io.recvline())
io.recvuntil(b"pubA: ");           pubA    = int(io.recvline())
io.recvuntil(b"pubB: ");           io.recvline()
io.recvuntil(b"Encrypted flag: "); ct_flag = io.recvline().strip().decode()

# Invia i nostri parametri
io.recvuntil(b"Enter your prime: ");        io.sendline(str(P_WEAK).encode())
io.recvuntil(b"Enter the generator: ");     io.sendline(b"2")
io.recvuntil(b"Enter your public value: "); io.sendline(str(0xFFFFFFFF + 1).encode())
io.recvuntil(b"Enter your message: ");      io.sendline(b"hello")

# Il server ci dà pubB = 2^privB mod P_WEAK
io.recvuntil(b"pubB: ")
pubB_weak = int(io.recvline())

# Pohlig-Hellman: trova privB
print("[*] Solving discrete log...")
privB = discrete_log(P_WEAK, pubB_weak, 2)
print(f"[*] privB = {privB}")

# Decifra la flag
shared = pow(pubA, privB, p_orig)
key    = hashlib.sha256(long_to_bytes(shared)).digest()[:16]
flag   = unpad(AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(ct_flag)), 16)
print(f"[*] FLAG: {flag.decode()}")
