
# pqc_crypto_package/__init__.py

"""
PQC Crypto Package (Using kyber-py, pydilithium, PyCryptodome)
This package provides functionalities for Post-Quantum Cryptography using standalone
Python libraries and symmetric encryption using PyCryptodome, including:
- Key generation for Kyber768 (kyber-py) and Dilithium3 (pydilithium)
- Key Encapsulation Mechanism (KEM) operations using Kyber768 (kyber-py)
- Symmetric encryption/decryption using AES-GCM (PyCryptodome)
- Digital signature generation and verification using Dilithium3 (pydilithium)
"""

# Ensure correct submodule names are used in imports
from .digi_sign import sign_message, verify_signature
from .kem_operations import kem_unwrap_symmetric_key, kem_wrap_symmetric_key
from .key_generation import generate_dilithium_keypair, generate_kyber_keypair
from .symmetric_ciphers import aes_gcm_decrypt, aes_gcm_encrypt

__all__ = [


    "generate_kyber_keypair",
    "generate_dilithium_keypair",
    "kem_wrap_symmetric_key",
    "kem_unwrap_symmetric_key",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "sign_message",
    "verify_signature"
]

print("PQC Crypto Package Initialized (Using kyber-py, pydilithium, PyCryptodome)")

