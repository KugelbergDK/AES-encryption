#!/usr/bin/python3

import base64
import sys
import os
import hashlib
import funcy
from Crypto import Random
from Crypto.Cipher import AES


'''
Chunks available
enc:    32
dec:    48

enc:    128
dec:    144

enc:    272
dec:    288

enc:    800
dec:    816

enc:    2048
dec:    2064

enc:    32768
dec:    32784

enc:    131072
dec:    131088


MAPLE LIGNING TIL CHUNKS
enc:=[32,128,272,800,2048]
dec:=[48,144,288,816,2064]
LinReg(enc,dec)
f(x):=1.0000x+16.0000
Forklaringsgrad er 1.0


speed testing
took 0.234 seconds to encrypt 102MB
took 0.531 seconds to decrypt 102MB
'''


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.iv = Random.new().read(AES.block_size)                 # 16 bytes
        self.key = hashlib.sha256(key.encode('utf-8')).digest()     # 32 bytes

    def encrypt(self, raw):
        raw = self._pad(raw.encode("utf-8"))
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(self.key + self.iv + cipher.encrypt(raw))  # Første 32 bytes er hash, næste er 16 bytes IV, næste er encrypted cipher

    def encryptFile(self, fileIn, fileOut, chunksize):
        print("Encrypting file: " + fileIn)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        with open(fileIn, "rb") as plain:
            with open(fileOut, "wb") as outFile:
                outFile.write(base64.b64encode(self.key + self.iv))

                while True:
                    chunk = plain.read(chunksize)
                    if len(chunk) == 0:
                        break
                    chunk = self._pad(chunk)
                    outFile.write(base64.b64encode(cipher.encrypt(chunk)))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        hashed = enc[:32]
        if self.key == hashed:
            print("Password correct... Continue")
        else:
            print("Wrong password")
            sys.exit(0)
        iv = enc[32:32 + 16]    # vælg iv
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[48:]))

    def decryptFile(self, fileIn, fileOut, chunksize):
        with open(fileIn, "rb") as encryptedFile:
            with open(fileOut, "wb") as decryptedFile:
                encrypted = base64.b64decode(encryptedFile.read(64))
                setup = encrypted[:48]         # READ KEY[32] and IV[16] = 32 + 16 = 48 | Hent key og IV
                if self.key == setup[:32]:
                    print("Password correct!")
                else:
                    print("WRONG PASSWORD")
                    sys.exit(0)

                print("Decrypting file: " + fileIn)

                iv = setup[32:]
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                encrypted = base64.b64decode(encryptedFile.read())
                chunks = list(funcy.chunks(chunksize, encrypted))
                for chunk in chunks:
                    decrypted_chunk = self._unpad(cipher.decrypt(chunk))
                    decryptedFile.write(decrypted_chunk)

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode('utf-8')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]



# EXAMPLES AND TESTING BELOW
os.system("clear")
aes = AESCipher(input("[+] Password: "))
#encrypted = aes.encryptFile("docs/1gb.txt", "docs/1gb-enc.txt", 131072)
decrypted = aes.decryptFile("docs/1gb-enc.txt", "docs/1gb.txt", 131088)
# Give me some space
print("\n")
'''
50mb
    enc: 
        real    0m3.701s
        user    0m0.344s
        sys     0m0.281s
    dec:
        real    0m2.129s
        user    0m0.375s
        sys     0m0.281s

148mb
    enc:
        real    0m2.522s
        user    0m0.891s
        sys     0m0.359s
    dec:
        real    0m3.077s
        user    0m1.219s
        sys     0m0.594s

478mb
    enc:
        real    0m5.281s
        user    0m2.906s
        sys     0m1.000s
    dec:
        real    0m6.738s
        user    0m3.453s
        sys     0m2.156s

1gb
    enc:
        real    0m11.788s
        user    0m8.047s
        sys     0m2.500s
    dec:
        real    0m16.306s
        user    0m9.641s
        sys     0m5.484s

'''
