
# demo_pqc_package.py
# Description: Demonstrates the functionalities of the pqc_crypto_package.

# Assuming 'pqc_crypto_package' is in the same directory or installed.
# If it's in the same directory, Python might need it to be explicitly added to path
# For simplicity, this script assumes it's discoverable (e.g., by running from parent directory
# or having __init__.py in the current directory making it a package itself - though less common for demo scripts)
# Or, more robustly, ensure PYTHONPATH is set or the package is installed.

import os
import sys

# Add the parent directory of 'pqc_crypto_package' to sys.path if running this script from a subdirectory
# or if 'pqc_crypto_package' is a sibling directory.
# This is a common way to handle local packages for testing.
# If pqc_crypto_package is installed via pip, this is not necessary.
# For this example, we'll assume the script is in the parent directory of pqc_crypto_package.
# Example:
# your_project/
# |-- demo_pqc_package.py
# |-- pqc_crypto_package/
#     |-- __init__.py
#     |-- key_generation.py
#     |-- ... other modules

try:

    # For generating a random symmetric key
    from Crypto.Random import get_random_bytes

    from pqc_crypto_package import (aes_gcm_decrypt, aes_gcm_encrypt,
                                    generate_dilithium_keypair,
                                    generate_kyber_keypair,
                                    kem_unwrap_symmetric_key,
                                    kem_wrap_symmetric_key, sign_message,

                                    verify_signature)
except ImportError as e:
    print(f"Error importing from pqc_crypto_package: {e}")
    print("Please ensure 'pqc_crypto_package' is in your PYTHONPATH, installed, or")
    print("this script is run from a directory where 'pqc_crypto_package' is accessible.")
    sys.exit(1)

def run_demonstration():
    """
    Runs a demonstration of the PQC crypto package functionalities.
    """
    print("--- Starting PQC Crypto Package Demonstration ---")

    # --- 1. Key Generation ---
    print("\n--- 1. Key Generation ---")
    print("Generating Kyber768 key pair for KEM...")
    kyber_pk_b64, kyber_sk_b64 = generate_kyber_keypair()
    if not (kyber_pk_b64 and kyber_sk_b64):
        print("ERROR: Kyber key generation failed. Exiting.")
        return
    print("Kyber768 Public Key (b64, first 30 chars):", kyber_pk_b64[:30] + "...")
    print("Kyber768 Secret Key (b64, first 30 chars):", kyber_sk_b64[:30] + "...")

    print("\nGenerating Dilithium3 key pair for Digital Signatures...")
    dilithium_pk_b64, dilithium_sk_b64 = generate_dilithium_keypair()
    if not (dilithium_pk_b64 and dilithium_sk_b64):
        print("ERROR: Dilithium key generation failed. Exiting.")
        return
    print("Dilithium3 Public Key (b64, first 30 chars):", dilithium_pk_b64[:30] + "...")
    print("Dilithium3 Secret Key (b64, first 30 chars):", dilithium_sk_b64[:30] + "...")

    # --- 2. Define a Sample Message ---
    print("\n--- 2. Sample Message ---")
    original_message_str = "This is a secret message for demonstration! It's PQC time!"
    original_message_bytes = original_message_str.encode('utf-8')
    print(f"Original Message: '{original_message_str}'")

    # --- 3. Symmetric Encryption (AES-GCM) ---
    print("\n--- 3. Symmetric Encryption (AES-GCM) ---")
    # Generate a random 256-bit (32-byte) AES key
    aes_key_bytes = get_random_bytes(32)
    print(f"Generated AES-256-GCM Key (hex): {aes_key_bytes.hex()}")

    print("Encrypting message with AES-GCM...")
    encrypted_package = aes_gcm_encrypt(original_message_bytes, aes_key_bytes)
    if not encrypted_package:
        print("ERROR: AES-GCM encryption failed. Exiting.")
        return
    print("AES-GCM Encryption successful.")
    print(f"  Nonce (b64): {encrypted_package['nonce_b64']}")
    print(f"  Ciphertext (b64, first 30): {encrypted_package['ciphertext_b64'][:30]}...")
    print(f"  Tag (b64): {encrypted_package['tag_b64']}")

    # --- 4. Key Encapsulation Mechanism (KEM - Kyber) ---
    print("\n--- 4. Key Encapsulation Mechanism (KEM with Kyber768) ---")
    print("Wrapping the AES key using Kyber public key...")
    wrapped_aes_key_b64 = kem_wrap_symmetric_key(aes_key_bytes, kyber_pk_b64)
    if not wrapped_aes_key_b64:
        print("ERROR: KEM key wrapping failed. Exiting.")
        return
    print("KEM Wrap successful.")
    print(f"Wrapped AES Key (b64, first 30): {wrapped_aes_key_b64[:30]}...")

    print("\nUnwrapping the AES key using Kyber secret key...")
    unwrapped_aes_key_bytes = kem_unwrap_symmetric_key(wrapped_aes_key_b64, kyber_sk_b64)
    if not unwrapped_aes_key_bytes:
        print("ERROR: KEM key unwrapping failed. Exiting.")
        return
    print("KEM Unwrap successful.")
    print(f"Unwrapped AES Key (hex): {unwrapped_aes_key_bytes.hex()}")

    # Verify if the unwrapped key matches the original AES key
    if aes_key_bytes == unwrapped_aes_key_bytes:
        print("SUCCESS: Unwrapped AES key matches the original AES key.")
    else:
        print("ERROR: Unwrapped AES key DOES NOT match the original AES key!")
        return # Critical error

    # --- 5. Symmetric Decryption (AES-GCM with unwrapped key) ---
    print("\n--- 5. Symmetric Decryption (AES-GCM with Unwrapped Key) ---")
    print("Decrypting message with the unwrapped AES key...")
    decrypted_message_bytes = aes_gcm_decrypt(encrypted_package, unwrapped_aes_key_bytes)
    if not decrypted_message_bytes:
        print("ERROR: AES-GCM decryption failed. Exiting.")
        return
    decrypted_message_str = decrypted_message_bytes.decode('utf-8')
    print(f"Decrypted Message: '{decrypted_message_str}'")

    # Verify if the decrypted message matches the original
    if original_message_bytes == decrypted_message_bytes:
        print("SUCCESS: Decrypted message matches the original message.")
    else:
        print("ERROR: Decrypted message DOES NOT match the original message!")
        return # Critical error

    # --- 6. Digital Signature (Dilithium3) ---
    print("\n--- 6. Digital Signature (Dilithium3) ---")
    # We will sign the original message bytes
    print("Signing the original message with Dilithium3 private key...")
    signature_b64 = sign_message(original_message_bytes, dilithium_sk_b64)
    if not signature_b64:
        print("ERROR: Message signing failed. Exiting.")
        return
    print("Message signing successful.")
    print(f"Signature (b64, first 30): {signature_b64[:30]}...")

    print("\nVerifying the signature with Dilithium3 public key...")
    is_verified = verify_signature(original_message_bytes, signature_b64, dilithium_pk_b64)
    if is_verified:
        print("SUCCESS: Signature verified successfully!")
    else:
        print("ERROR: Signature verification failed!")

    # Test verification with wrong message
    print("\nVerifying the signature with a TAMPERED message...")
    tampered_message_bytes = b"This is not the original message."
    is_verified_tampered = verify_signature(tampered_message_bytes, signature_b64, dilithium_pk_b64)
    if not is_verified_tampered:
        print("SUCCESS: Signature verification correctly FAILED for tampered message.")
    else:
        print("ERROR: Signature verification INCORRECTLY PASSED for tampered message.")

    # Test verification with wrong public key
    print("\nVerifying the signature with a WRONG public key...")
    # Generate a new dummy Dilithium key pair for this test
    wrong_dilithium_pk_b64, _ = generate_dilithium_keypair()
    if wrong_dilithium_pk_b64:
        is_verified_wrong_pk = verify_signature(original_message_bytes, signature_b64, wrong_dilithium_pk_b64)
        if not is_verified_wrong_pk:
            print("SUCCESS: Signature verification correctly FAILED for wrong public key.")
        else:
            print("ERROR: Signature verification INCORRECTLY PASSED for wrong public key.")
    else:
        print("Skipped wrong public key test due to key generation error.")


    print("\n--- PQC Crypto Package Demonstration Finished ---")

if __name__ == "__main__":
    run_demonstration()
