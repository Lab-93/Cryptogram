# Cryptography Methods
This package serves as a neat little wrapper for pythons ```cryptography``` module;
which offers simple methodology for encrypting and decrypting secrets in a manner
easily acessed by other packages with minimal overhead.


# Installation
To install the package, simply type ```pip install CryptographyMethods```.


# Usage
To use the package in your own code add ```import CryptographyMethods``` to the
header section of your script.

```CryptographyMethods``` offers one-way and two-way encryption;
```CryptographyMethods.SHA256()``` is the one-way implementation, it simply accepts
a string argument and returns the hash of whatever value is given.


## Build the Key
In order to utilize two-way encryption, an encryption key must first be generated.
Give a string to ```CryptographyMethods.BuildKey()``` to do so.

Next, to encrypt a string call ```CryptographyMethods.Encryption(KEY, 'secret')```.  
To decrypt the string, call ```CryptographyMethods.Decryption(KEY, 'encrypted_secret')```
with the same encryption key.