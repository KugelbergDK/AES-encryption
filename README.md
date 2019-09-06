# AES encryption

This is a python CLI tool to encrypt and decrypt data using AES-256. This works with python3 and this is not tested with python2.

## Installation
You need to install PyCrypto in order to make this work.

	$ pip install pycrypto hashlib base64 funcy


## How to
Simply use the class.

### Setting up the password for the object


```python
aes = AESCipher(input("[+] Password: "))

```

Or

```python
password = input("[+] Password: ")
aes = AESCipher(password)

```

### Encryption
To encrypt string, use

```python
print(aes.encrypt(input("Your data: ")).decode("utf-8"))

```

To encrypt file


```python
aes.encryptFile("plaintext.txt", "encrypted.txt", 131072)

```

The 3rd parameter is the chunk size. How much data you want to encrypt each time, this may be different from computer to computer


### Decryption

To decrypt string, use

```python
print(aes.decrypt(input("Your encrypted data: ")).decode("utf-8"))

```


To decrypt file, use


```python
print(aes.decryptFile("encrypted.txt", "decrypted.txt", 131088)

```
This works only with certain chunksizes.

### Chunksizes

Chunksizes in this script is quite unique. 
Make sure when encrypting to use a chunksize there is divisible with 16. 

When working with files, the setup is like this:

```
{key[32 bytes]}{IV[16 bytes]}{chunk[chunksize]}{chunk[chunksize]}...

```

It is important to use the chunksizes written down in the code (out-commented in the first section of the code.)

You can try to test it by yourself, but I can't promise that it will work.
