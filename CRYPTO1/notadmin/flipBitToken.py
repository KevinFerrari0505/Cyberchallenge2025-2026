token = "2c55cd6af6f6381e06643932ed916592635e2f86a0246a119918a5705b18dba367fdcb6f6216dfdf61046c576dcda513" #cambia ogni volta
data = bytearray.fromhex(token)

# posizione dello '0' nel primo blocco
pos = 15  

data[pos] ^= 1

print(data.hex())
