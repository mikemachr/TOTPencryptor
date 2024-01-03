import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidKey, UnsupportedAlgorithm
import os
import sys
import pyotp
import qrcode
from PIL import Image

def pad(data, block_size: int) -> bytes:
    '''Adds needed padding for encryption'''
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()

def unpad(data, block_size: int) -> bytes:
    '''Removes padding from encrypted file'''
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def derive_key(password: str, salt: bytes, key_length: int) -> bytes:
    '''Derives key from the one provided by user'''
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def generate_totp_secret():
    '''Initializes secret for TOTP'''
    return pyotp.random_base32()

def generate_totp_qr_code(secret, account_name, issuer_name):
    '''Generates QR code associated to TOTP secret'''
    totp = pyotp.TOTP(secret)
    label = f"{issuer_name}:{account_name}"
    provisioning_uri = totp.provisioning_uri(name=label)
    img = qrcode.make(provisioning_uri)
    img.show()

def verify_totp_code(secret, user_provided_code):
    '''Verifies if provided TOTP code matches expected code'''
    totp = pyotp.TOTP(secret)
    return totp.verify(user_provided_code, valid_window=5)  # Set valid_window to 5 seconds


def handle_duplicate_file(file_path):
    '''Handles the case when decrypting results in duplicated file'''
    base, ext = os.path.splitext(file_path)
    new_path = file_path

    count = 1
    while os.path.exists(new_path):
        new_path = f"{base}({count}){ext}"
        count += 1

    return new_path

def encrypt_file(file_path, password, use_totp=False) -> bytes:
    '''Encrypts given file using derived key from password. Appends IV and TOTP secret
    (if applicable) to cypher-text'''
    salt = os.urandom(16)
    key = derive_key(password, salt, 32)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext, 16)) + encryptor.finalize()

    # Generate TOTP secret if required
    totp_secret = generate_totp_secret() if use_totp else ""

    # Save TOTP secret in a file if required
    if use_totp:
        generate_totp_qr_code(totp_secret, os.path.basename(file_path), "pythonCypher")
        # Save TOTP secret along with the encrypted file
        with open(file_path + '.enc', 'wb') as file:
            file.write(salt + iv + len(totp_secret).to_bytes(2, 'big') + totp_secret.encode('utf-8') + ciphertext)
    else:
        # Save encrypted file without TOTP secret
        with open(file_path + '.enc', 'wb') as file:
            file.write(salt + iv + b'\x00\x00' + ciphertext)

    print("Encryption successful!")

def decrypt_file(encrypted_file_path, password, totp_code=None) -> bytes:
    '''Attempts to decrypt file, reports encountered errors, if any.'''
    try:
        with open(encrypted_file_path, 'rb') as file:
            data = file.read()

        salt = data[:16]
        iv = data[16:32]
        totp_secret_length = int.from_bytes(data[32:34], 'big')
        totp_secret_encoded = data[34:34+totp_secret_length]
        ciphertext = data[34+totp_secret_length:]

        # Convert TOTP secret from bytes to string
        totp_secret = totp_secret_encoded.decode('utf-8')

        # Verify TOTP code if provided
        if totp_code is not None:
            print(f"Provided TOTP Code: {totp_code}")
            if not verify_totp_code(totp_secret, totp_code):
                print("Invalid TOTP code.")
                sys.exit(1)
        elif totp_secret_length > 0:
            print("Error: TOTP code is required for decryption.")
            sys.exit(1)

        key = derive_key(password, salt, 32)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = unpad(decryptor.update(ciphertext) + decryptor.finalize(), 16)

        encrypted_file_path = handle_duplicate_file(encrypted_file_path[:-4])

        with open(encrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        print("Decryption successful!")

    except (InvalidSignature, InvalidKey, UnsupportedAlgorithm) as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        sys.exit(1)


def main():
    '''Executes main logic, handles arguments as provided using command line'''
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files with optional TOTP authentication.")
    parser.add_argument("file", help="File to encrypt or decrypt")
    parser.add_argument("mode", choices=["e", "d"], help="Mode: 'e' for encrypt, 'd' for decrypt")
    parser.add_argument("key", help="Encryption/Decryption key")
    parser.add_argument("--totp", action="store_true", help="Enable TOTP authentication")
    parser.add_argument("--totp-code", help="TOTP code for decryption")

    args = parser.parse_args()

    if args.mode == 'e':
        encrypt_file(args.file, args.key, args.totp)
    elif args.mode == 'd':
        decrypt_file(args.file, args.key, args.totp_code)
    else:
        print("Invalid mode. Use 'e' for encrypt or 'd' for decrypt.")
        sys.exit(1)

if __name__ == "__main__":
    main()
