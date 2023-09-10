import sys
from hashlib import sha256
import binascii
from cryptography.fernet import Fernet
import secrets
import hashlib
import hmac
import os
import unicodedata

from bip32utils import BIP32Key
import bip39_  # single package, not from bip_utils
from eth_keys import keys

from bip_utils import (
    Bip39MnemonicGenerator,
)


random_key = Fernet.generate_key()
# print(key)


def quick_dec(phrase: str, encrypted_in: str):
    crypto = Fernet(phrase.encode())  # 44 byte key is ok
    decrypted = crypto.decrypt(encrypted_in.encode())  # bytearray(encrypted_in, 'utf-8'))

    return decrypted.decode("utf-8")  # str(decrypted) # str() is b'string'


def quick_enc(phrase: str):
    crypto = Fernet(phrase.encode())  # 44 byte key is ok
    encrypted = crypto.encrypt(bytes(input('paste raw mne'), 'utf-8'))  # same as encode

    return encrypted


def to_eth_keys(mnemonic_phrase, default_start=0, keys_count=100, mode='', derivation='master'):
    '''
    mode = 'url','all','address' to determine return format:

    default using 'm' derivation - for client1,2,3
    'eth' derivation for cosmos
    '''

    # Derive the seed from the mnemonic phrase
    seed = bip39_.phrase_to_seed(mnemonic_phrase)

    # Generate the master private key from the seed
    master_key = BIP32Key.fromEntropy(seed)
    if derivation == 'eth':
        ethereum_key = BIP32Key.fromExtendedKey(
            BIP32Key.fromEntropy(seed).ExtendedKey("m/44'/60'/0'/0/")
        )
        master_key = ethereum_key

    # Derive the first 100 private and public key pairs
    key_list = []
    for i in range(keys_count):
        # Derive the child key at index i
        child_key = master_key.ChildKey(i)

        # Derive the Ethereum private key from the child key
        private_key_hex = child_key.PrivateKey().hex()

        # Create an Ethereum private key object
        private_key = keys.PrivateKey(bytes.fromhex(private_key_hex))

        # Derive the Ethereum address from the public key
        address = private_key.public_key.to_checksum_address()

        # Print the private key, public key, and address
        # print(f'{{"id":{i+1},"privateKey": {private_key_hex},"address":"{address}"}},')
        # print(f"Public key #{i+1}: {private_key.public_key.to_hex()}")
        if mode == 'url':
            key_list.append(
                f"<a href=https://explorer.zksync.io/address/{address}>{i+1} {address}</a>"
            )
        elif mode == 'all':
            key_list.append({"id": i + 1, "privateKey": private_key_hex, "address": address})
        elif mode == 'address':
            key_list.append(f"{address}")
        else:
            key_list.append(f"{i+1},{address}")

    return key_list


def mne_to_BTCkeys(mnemonic_phrase: str):
    # Normalize the mnemonic phrase
    normalized_mnemonic = unicodedata.normalize("NFKD", mnemonic_phrase)

    # Derive the seed from the mnemonic phrase
    seed = mnemonic_to_seed(normalized_mnemonic)

    # Generate the master private key from the seed
    master_key = BIP32Key.fromEntropy(seed)

    # Derive the first 100 private and public key pairs
    for i in range(100):
        # Derive the child key at index i
        child_key = master_key.ChildKey(i)

        # Generate the private and public keys from the child key
        private_key = child_key.PrivateKey().hex()
        public_key = child_key.PublicKey().hex()

        print(f"Private key #{i+1}: {private_key}")
        print(f"Public key #{i+1}: {public_key}")

    bip_f = "c:\\private\wallets\\BIP39.txt"
    with open(bip_f) as f:
        content = f.read()
    bip = content.split("\n")


def to_mnemonic(data):

    """
    data: secrets.token_bytes(strength // 8)
        b'\\xebr\\x17D*t\\xae\\xd4\\xe3S\\xb6\\xe2\\xebP1\\x8b'
    """
    if len(data) not in [16, 20, 24, 28, 32]:  # I added 64
        raise ValueError(
            "Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d)."
            % len(data)
        )
    h = sha256(data).hexdigest()
    b = (
        bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8)
        + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
    )
    result = []
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        result.append(bip[idx])
    """if (
        detect_language(" ".join(result)) == "japanese"
    ):  # Japanese must be joined by ideographic space.
        result_phrase = u"\u3000".join(result)
    else:"""
    result_phrase = " ".join(result)
    return result_phrase


if __name__ == "__main__":
    to_eth_keys(os.getenv('your_memonic'))
    # print(quick_enc(os.getenv('yourphrase')))
