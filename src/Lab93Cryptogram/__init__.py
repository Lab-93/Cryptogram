#!/bin/python3
from base64 import urlsafe_b64encode
import hashlib as hashlib
from cryptography.fernet import Fernet


class CryptographyMethodsAPI():
    """
    The CryptographyMethodsAPI class enscapulates methods used for keeping
    secrets in both one-way and two-way forms.

    SHA-256 is delivered in a much simpler syntax than the default method
    utilized by hashlib; the CryptographyMethods.SHA256 object merely
    requires a secret to be hashed and delivers the hexdigest of the
    resulting byte object.

    For two-way secret keeping CryptographyMethods.Encryption and
    CryptographyMethods.Decryption are offered; both of which utilize the
    CryptographyMethods.BuildKey function for locking and unlocking secrets,
    respectively.
    """
  
  
  
  
    def __init__(self):
      self = self

    class ValueNotFound(Exception):
        def __init__(self, message):
            print(message); exit()
                
  
  
    def SHA256(self, secret: str):
      """
      Create a SHA-256 hash of whatever value is given as 'secret' and
      return the the hexdigest of the bytes-encoded secret.
      """
      return hashlib.sha256(secret.encode())\
                    .hexdigest()
  
  
    def BuildKey(self, key: str):
      """
      Create a two-way encryption token using the first 32
      digits of the hash of a given string named 'key'.
    
      The results are then encoded in urlsafe-base64 bytes
      and returned to the caller.
      """
      basecode = self.SHA256(str(key))[:32]
      return urlsafe_b64encode(basecode.encode())
  
  
    def Encryption(self, phrase: bytes, target: str):
      """
      Encrypt a 'target' string using a byte 'phrase' provided by
      CryptographyMethods.BuildKey as an encryption token.
      """
      intelligence = Fernet(phrase)
      return intelligence.encrypt(bytes(target, 'utf-8'))
  
  
    def Decryption(self, phrase: bytes, target: str):
      """
      Decrypt a 'target' string using a byte 'phrase' provided by
      CryptographyMethods.BuildKey as an encryption token.
      """
      intelligence = Fernet(phrase)
      return intelligence.decrypt(target).decode()
  
  
    def RetrieveCredentials( self,
                             credential: str = "alpaca_key", username: str = "admin",
                             keyfile:    str = "/server/credentials/admin.key",
                             database:   str = "server/database/admin"):
        """
        """


        connection = connect(database); cursor = connection.cursor()

        sqlSelectCredential = "SELECT hash FROM credentials WHERE platform = ? AND user = '?';"

        _results = connection.execute( sqlSelectCredential, (credential, username) )\
                             .fetchall()

        if len(_results) > 0: _results = _results[0][0]
        else: raise ValueNotFound(
            f"Could not find {credential} in the database."
        )

        with open(keyfile, 'r') as secret_key:
            secretkey = self.BuildKey( secret_key.read()\
                                                 .split("\n")[1] ) )
        return self.Decryption( secretkey,
                                _results   )

