#!/usr/bin/env python
# coding: utf-8

# # Lab-93 Authentication Validation
# This system ensures that the Lab can operate using as many 'username required' platforms as required for runtime as
# potentially needed.  
# 
# Or, This system remembers our passwords for us!    
# 
# The Lab93AuthenticationValidation package ensures that 

# ## Module Imports

# In[ ]:


import argparse
from sqlite3 import connect
from logging import getLogger, info, debug, exception
import CryptographyMethods


# ## Rebuild Encryption Key

# In[ ]:


def BuildPrivateKey(keyfile):
  """ This function uses a given file as the base to re-build the key
  used to encrypt private credentials known to the administrator. """
  getLogger()
  info(f"Reading private key from {keyfile}.")

  with open(keyfile, "r") as privkey:
    privkey = privkey.readlines()
  
  privkey.pop(0); privkey.pop(-1)

  key = ""
  for line in privkey: key += line

  return CryptographyMethods.BuildKey(key)


# ## Unlock Credentials
# This method takes the previously rebuilt key and uses it to decrypt a given string encrypted with that key. 

# In[ ]:


def CredentialUnlocker( keyfile, credential ):
  """ This function simply unencrypts a given bytestring,
  assuming the correct keyfile is supplied. """
  getLogger()
  info("Unlocking credentials.\n")

  return CryptographyMethods.Decryption(
    BuildPrivateKey(keyfile),
    credential
  ).decode()


# ## Credential Storage

# ### Single-Key

# In[ ]:


def Store_SingleKey(keyfile, database, credential, platform):
  """
  This function will add a new credential to the database.
  If the singleKey argument is true then it just encrypts the value of
  the credential argument at face value; but if it is set to false
  then it is assumed that the argument is a dictionary containing 'key'
  and 'secret' entries.
  """
  # Use logging, if able.
  getLogger()

  # Establish connection to the credentils database.
  debug(f"Connecting to credential database at {database}")
  try: 
    connection = connect(database)
    cursor = connection.cursor()
    execute = cursor.execute
    debug("Connection successful.")

  except Exception as error:
    exception(
      f"There was a problem trying to connect to the credential database."
      f"{error}"
    ); return error


  cryptogram = CryptographyMethods


  # Encrypt the given credential using Cryptography Methods.
  info(f"Applying encryption to secret credential.")
  try:
    secret = cryptogram.Encryption( BuildPrivateKey(keyfile), credential )

  except Exception as error:
    exception(f"There was a problem with encrypting the credential.\n{error}")
    return error


  # Create a new column for the freshy generated secret.
  info(f"Creating {platform} column within credentials database.")
  try: execute("ALTER TABLE credentials ADD {} BYTES".format(platform.lower()))

  except Exception as error:
    exception(f"There was a problem trying to create a new column.\n{error}")
    return error


  # Add the secret to the column
  info(f"Adding credential to {platform} column.")
  try: execute("UPDATE credentials SET {}=? WHERE username='admin';"\
       .format(platform.lower()), (secret,)
  )

  except Exception as error:
    exception(f"There was a problem trying to write the credential to the table.")
    return error

  info() 
  return connection.commit()


# ### Multi-Key

# In[ ]:


def Store_MultiKey(keyfile="tests/test.key", database="tests/test.db", credential="test", platform="test"):
  """
  """
  getLogger()

  # Establish connection to the credentils database.
  debug(f"Connecting to credential database at {database}")
  try: 
    connection = connect(database)
    cursor = connection.cursor()
    execute = cursor.execute
    debug("Connection successful.")

  except Exception as error:
    exception(
      f"There was a problem trying to connect to the credential database."
      f"{error}"
    ); return error


  cryptogram = CryptographyMethods


  info("Multi-Key credentials selected.")


  # Encrypt the platform key credential.
  info("Applying encryption to platform key credential")
  try: 
    credential['key'] = CryptographyMethods.Encryption( BuildPrivateKey(keyfile), credential['key'] )
    info("Encryption successful.")
  
  except Exception as error:
    exception(f"There was a problem with encrypting the credential.\n{error}")
    return error


  # Create a $platform_key column for the credentials table.
  info(f"Creating {platform}_key column within credentials database.")
  try:
    execute( "ALTER TABLE credentials ADD {} BYTES".format(f"{platform}_key"))
    info("Column {platform}_key created.")

  except Exception as error:
    exception(f"There was a problem with encrypting the credential.\n{error}")
    return error


  # Add the encrypted key to the $platform_key column.
  info(f"Adding platform key to {platform}_key column.")
  try:
    execute(
      "UPDATE credentials SET {}=? WHERE username='admin';"\
        .format(f"{platform}_key"),
        (credential['key'],)
    )
    info("Addition successful.")

  except Exception as error:
    exception(f"There was a problem with encrypting the platform key:\n{error}")
    return error


  # Encrypt the platform secret credential.
  info(f"Attempting to encrypt the platform secret credential.")
  try:
    credential['secret'] = cryptogram.Encryption(BuildPrivateKey(keyfile), credential['secret'])
    info("Encryption successful.")

  except Exception as error:
    exception(f"There was a problem with encrypting the platform secret:\n{error}")
    return error


  # Create a $platform_secret column for the secret credential.
  info(f"Creating {platform}_secret column within the credentials table.")
  try:
    execute("ALTER TABLE credentials ADD {} BYTES".format(f"{platform}_secret"))
    info("Column {platform}_key creation successful.")

  except Exception as error:
    exception(f"There was a problem with encrypting the {platform}_secret \n{error}")
    return error


  # Store the encrypted secret within the credentials table.
  info(f"Adding credential secret to {platform}_key column.")
  try:
    execute(
      "UPDATE credentials SET {}=? WHERE username='admin';".format(f"{platform}_secret"),
        (credential['secret'],)
    )
    info("Addition successful.")

  except Exception as error:
    exception(f"There was a problem with encrypting the credential.\n{error}")
    return error


  # Save your work!
  info("Database write done, saving commits to journal.\n")
  return connection.commit()


# ## Unlock Credentials
# All credentials need to be decrypted before passing back to the caller; so this method 

# In[ ]:


def CredentialUnlocker( keyfile, credential ):
  """ This function simply unencrypts a given bytestring,
  assuming the correct keyfile is supplied. """
  getLogger()
  info("Unlocking credentials.\n")

  cryptogram = CryptographyMethods

  return cryptogram.Decryption(
    BuildPrivateKey(keyfile),
    credential
  ).decode()


# ## Retrieve Single-Key Credential

# In[ ]:


def SingleKeyAPICredentials( platform, credabase, keyfile ):
  """
  This function retrieves the key for any API that only requires a single
  credential for validation.
  """

  getLogger()

  debug(f"Connecting to credential database at {credabase}\n")
  connection = connect(credabase)
  cursor = connection.cursor()
  execute = cursor.execute

  cryptogram = CryptographyMethods


  info(f"Retrieving single-key credentials for {platform}.\n")
  secrets = execute(
    "SELECT ? FROM credentials WHERE username = 'admin'",
    (platform,)
  ).fetchall()[0][0]

  return cryptogram.Decryption(
    BuildPrivateKey(keyfile),
    secret
  ).decrypt()


# In[ ]:


def MultiKeyAPICredentials( platform, credabase, keyfile ):
  """ This function retrieves the multi-key authentication tokens for any API
  that requires more than one credential to validate sign-on. """
  getLogger()

  debug(f"Connecting to credential database at {credabase}\n")
  connection = connect(credabase)
  cursor = connection.cursor()
  execute = cursor.execute

  info(f"Retrieving multi-key credentials for {platform}.\n")
  secrets = execute(
    "SELECT {}, {} FROM credentials WHERE username = 'admin';"\
    .format(
      f"{platform}_key",
      f"{platform}_secret"
    )
  ).fetchall()[0]

  credentials = { "key": CredentialUnlocker(keyfile, secrets[0]),
                  "secret": CredentialUnlocker(keyfile, secrets[1]) }

  return credentials

