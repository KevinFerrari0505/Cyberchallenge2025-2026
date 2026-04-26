from Crypto.Util.number import getPrime, bytes_to_long
from functools import reduce
from secret import flag

primes = [getPrime(64) for _ in range(16)]
n = reduce((lambda x, y: x * y), primes)
ct = pow(bytes_to_long(flag),65537,n)
print(f"N: {n}")
print("e: 65537")
print(f"Ciphertext: {ct}")
