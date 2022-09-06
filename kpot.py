import struct
import sys

class KpotStruct:
    def __init__(self,s):
        self.key=s[0]
        self.size=s[1]
        self.address=s[2] #VirtualAdress
        self.offset =s[2] - 0x400c00

def decrypt(key,data):
    dec = bytearray(data)
    for i in range(len(dec)):
        dec[i] = dec[i] ^ key
    return dec.decode()

f = open(sys.argv[1], "rb")
f.seek(0xbb8) #file offset of the structure arrays' beggin

while True:
    s=struct.unpack("<HHI", f.read(8))
    ks=KpotStruct(s)

    if ks.key & 0xff00:
        break

    print("Decrypting string at ",hex(ks.address)," with key ",hex(ks.key)," ...")

    pos = f.tell()
    #print(hex(ks.address))
    f.seek(ks.offset)
    enc = f.read(ks.size)

    print(decrypt(ks.key, enc))
    f.seek(pos)

f.close()