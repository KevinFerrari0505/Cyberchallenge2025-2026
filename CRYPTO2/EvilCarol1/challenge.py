#!/usr/bin/env python3

import signal
import os
import random
import hashlib
from Crypto.Util.number import getStrongPrime, long_to_bytes, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

TIMEOUT = 300

assert("FLAG" in os.environ)
FLAG = os.environ["FLAG"]
assert(FLAG.startswith("CCIT{"))
assert(FLAG.endswith("}"))

assert("NBITS" in os.environ)
NBITS = int(os.environ["NBITS"])


def handle():
    p = getStrongPrime(NBITS)
    g = 2

    def gen_key():
        s = random.randint(0, 2**NBITS)
        return s, pow(g, s, p)

    privA, pubA = gen_key()
    privB, pubB = gen_key()

    shared_secret = pow(pubA, privB, p)
    key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(FLAG.encode(), 16)).hex()

    print("See how Alice successfully exchanged a message with Bob:")
    print(f"p: {p}")
    print(f"pubA: {pubA}")
    print(f"pubB: {pubB}")
    print(f"Encrypted flag: {ct}")
    print()
    print("Now you can exchange messages with Bob too!")
    p = int(input("Enter your prime: "))
    g = int(input("Enter the generator: "))
    pub = int(input("Enter your public value: "))
    msg = input("Enter your message: ").encode()

    assert isPrime(p), "Please provide a prime p"
    assert p.bit_length() >= NBITS, "Please use a bigger prime"

    pubB = pow(g, privB, p)
    shared_secret = pow(pub, privB, p)
    key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(msg, 16)).hex()
    print(f"pubB: {pubB}")
    print(f"Here's the encrypted message: {ct}")


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
