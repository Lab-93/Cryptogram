# Lab93-Cryptogram
A _small_ tool for encrypting and decrypting secrets.

## Installation
```
pip install --upgrade Lab93Cryptogram
```


## Usage
The ```CryptographyMethodsAPI``` object has to be instantiated before any
of the inner methods can be accessed.
```
from Lab93Cryptogram import CryptogaphyMethodsAPI as cryptogram
```


### SHA-256
SHA-256 offers a nearly unbreakable one-way encryption for hashing a secret
meant to validate another parties identity.
```
username = cryptogram().SHA256( "hunter" )
password = cryptogram().SHA256( "lol you thought" )
```


### BuildKey
In order to use two-way encryption there exists the need for a secret key
known only to the parties intended to access the secret.  To generate a key
with the CryptographyMethodsAPI, we simply give a string to the BuildKey
function; which then converts the string to a SHA256 hash and takes the first
32 bytes from the result and uses that as the key.
```
encryption_key = cryptogram().BuildKey( f"{username}{password}" )
```


### Encryption
To encrypt a two-way credential, simply plug the previously built key along
with the target string to the _Encryption_ method like so.
```
encrypted_secret = cryptogram().Encryption( encryption_key,
                                            "This would be an API key." )
```


### Decryption
Decryption works exactly the same as Encryption; by taking the encryption key
and the target string previously encrypted it reverses the obsfuscation brough
by the previous action.
```
decrypted_secret = cryptogram().Decryption( encryption_key,
                                            encrypted_secret )
```
