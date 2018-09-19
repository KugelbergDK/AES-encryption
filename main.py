#!/usr/bin/python3

import base64
import sys
import os
import hashlib
import funcy
from Crypto import Random
from Crypto.Cipher import AES


'''
Chunks der virker
enc:    32
dec:    48

enc:    128
dec:    144

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
                    print("BYTE SIZE:\t " + str(len(chunk)))
                    #print("Chunk written")
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
        print("Decrypting file: " + fileIn)
        with open(fileIn, "rb") as encryptedFile:
            with open(fileOut, "wb") as decryptedFile:
                encrypted = base64.b64decode(encryptedFile.read(64))
                setup = encrypted[:48]         # READ KEY[32] and IV[16] = 32 + 16 = 48 | Hent key og IV
                if self.key == setup[:32]:
                    print("Password correct!")
                else:
                    print("WRONG PASSWORD")
                    sys.exit(0)

                iv = setup[32:]
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                encrypted = base64.b64decode(encryptedFile.read())
                chunks = list(funcy.chunks(chunksize, encrypted))
                for chunk in chunks:
                    print("BYTE SIZE:\t " + str(len(chunk)))
                    decrypted_chunk = self._unpad(cipher.decrypt(chunk))
                    decryptedFile.write(decrypted_chunk)
                # print(self._unpad(cipher.decrypt(base64.b64decode(encryptedFile.read()))))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode('utf-8')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


os.system("clear")
aes = AESCipher(input("[+] Password: "))
encrypted = aes.encryptFile("secret.txt", "secret-out.txt", 128)
# Give me some space
print("\n")

decrypted = aes.decryptFile("secret-out.txt", "dekrypteret.txt", 144)
# print(decrypted)
''' EXAMPLES

aes = AESCipher(input("[+] Password: "))

print("\n\n" + aes.encrypt(input("[+] Your message to encrypt: ")).decode("utf-8"))

print(bcolors.OKGREEN + "\n\n[+] DONE!" + bcolors.ENDC)

aes = AESCipher(input("[+] Password for decryption: "))
print ("\n\n")
print(aes.decrypt("pmWkWSBCL51Bfkhn79xPuKBKHz//H6B+mY6G9/eieuONIPFiKUB/vWlImZ/Vz6eduKroJu5QCVxMo3mU7oxocJ6VUsFryE8Z46wV3ZwSdYWGKPoGk7qGZM9LAl40QGxf3QWuQC/k3f9/I6Oia+4eqg==").decode("utf-8"))


'''
