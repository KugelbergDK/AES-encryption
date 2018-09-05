# AES encryption

This is a python CLI tool to encrypt and decrypt data using AES-256. This works with python3 and this is not tested with python2.

## Installation
You need to install PyCrypto in order to make this work.

	$ pip install pycrypto hashlib base64


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

### Just tell me how to use this thing

#### Encryption
To encrypt string, use

```python
print(aes.encrypt(input("Your data: ")).decode("utf-8"))

```

To encrypt file


```python
aes.encryptFile("plaintext.txt", "encrypted.txt", 64 * 1024)

```

The 3rd parameter is the chunk size. How much data you want to encrypt each time, this may be different from computer to computer

#### Decryption

To decrypt string, use

```python
print(aes.decrypt(input("Your encrypted data: ")).decode("utf-8"))

```


To decrypt file, use - THIS DOES NOT WORK YET

```python
print(aes.decryptFile("encrypted.txt", "decrypted.txt", 64 * 1024)

```