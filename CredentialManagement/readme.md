# Credential Management
This package provides an interface between the ```CryptographyMethods``` package
and the Lab-93 credential database.

It is used to facilitate the handing-off of highly sensitive API credentials to
the automated systems that use them.


# Credential Types
The system allows for two separate types of API credentials; ```Single-Key```,
for API's that take a more lax approach to securing less-sensitive materials,
and ```Multi-Key``` for API's that use a key/secret combination validation
system.


# Usage
The ```CredentialManagement``` system assumes three things:  
  - __An already existing SQLite3 database with a 'credentials' table.__
  - __A 'username' column within that table with a single row containing the value *admin*.__
  - __The user has an ssh token.__

In order to abstract away the need to remember an encryption key, the system uses
a private ssh key as the seed to create the key.


## Installation
To download the package, type ```pip install CredentialManagement``` to your console.


## Storage
There are two methods for storing credentials to the database.  ```CredentialManagement.Store_SingleKey``` and ```CredentialManagement.Store_MultiKey```.
Both require a  __*database*__, __*keyfile*__, __*credential*__, and __*platform*__
argument, but the ```SingleKey``` __*credential*__ argument is a simple string, while
the ```MultiKey``` __*credential*__ argument is a dictionary with the keys ```'key'``` and ```'secret'``` containing their respective API counterparts.