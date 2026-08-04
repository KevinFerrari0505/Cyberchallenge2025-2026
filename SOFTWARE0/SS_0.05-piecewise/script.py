from pwn import *

conn = remote("piecewise.challs.cyberchallenge.it", 9110)
while True:
    try:
        line = conn.recvline().strip().decode().split()
        result = None
        if("empty" in line):
            result = p8(10)
        else:
            bits = line[8].split("-")[0]
            endian = line[9].split("-")[0]
            packer = make_packer(bits, endian=endian,sign='unsigned')
            result = packer(int(line[5]))
        conn.send(result)
        print(conn.recvline())
    except Exception as e:
        conn.close()
        print(e)
        quit()
