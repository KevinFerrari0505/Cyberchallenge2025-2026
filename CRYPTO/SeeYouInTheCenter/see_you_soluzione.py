import base64
import string
import itertools

# ciphertext della challenge
c = "QSldSTQ7HkpIJj9cQBY3VUhbQ01HXD9VRBVYSkE6UWRQS0NHRVE3VUQrTDE="

# decode base64
cipher = base64.urlsafe_b64decode(c).decode('ascii')

def encrypt(clear, key):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 128)
        enc.append(enc_c)
    return "".join(enc)

def decrypt(enc, key):
    dec = []
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((128 + ord(enc[i]) - ord(key_c)) % 128)
        dec.append(dec_c)
    return "".join(dec)

alphabet = string.ascii_lowercase

plaintext = "See you later in the city center"

# tabella per meet-in-the-middle
table = {}

# tutte le k1
for k in itertools.product(alphabet, repeat=4):
    k1 = "".join(k)

    d = encrypt(plaintext, k1)
    d = base64.urlsafe_b64encode(d.encode()).decode()

    table[d] = k1

# tutte le k2
for k in itertools.product(alphabet, repeat=4):
    k2 = "".join(k)

    d2 = decrypt(cipher, k2)

    if d2 in table:
        k1 = table[d2]
        KEY = k1 + k2

        print("FLAG:", "CCIT{" + KEY + "}")
        break

print(len(table))
