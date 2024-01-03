# Python file encryptor/decryptor with TOTP 

This file can be used to encrypt and decrypt files using AES256, and optionally use TOTP. 

When prompted to use TOTOP file is encrypted, then the associated QR code is shown on screen. 

Cypher key is derived from password provided by user, SALT, AES IV and TOTP secrey(if any) are saved 
into the cyphertext file.
