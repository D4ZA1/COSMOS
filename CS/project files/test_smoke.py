

from conftest import dilithium_key_pair_alice  # Fixture for Dilithium keys
from conftest import kyber_key_pair_alice  # Fixture for Kyber keys
from conftest import medium_message_bytes  # Fixture for a sample message
from conftest import specific_aes_key_32_bytes  # Fixture for a sample AES key
from conftest import requires_dilithium, requires_kyber
from pqc_crypto_package import (aes_gcm_decrypt, aes_gcm_encrypt,
                                generate_dilithium_keypair,
                                generate_kyber_keypair,
                                kem_unwrap_symmetric_key,
                                kem_wrap_symmetric_key, sign_message,
                                verify_signature)


@requires_kyber



def test_smoke_kyber_key_generation_and_types():
    """SMOKE: Kyber key generation produces non-None string outputs of expected types."""
    print("\nSMOKE: Testing Kyber key generation...")
    pk, sk = generate_kyber_keypair()
    assert pk is not None, "Kyber public key should not be None"
    assert sk is not None, "Kyber secret key should not be None"
    assert isinstance(pk, str), "Kyber public key should be a string"
    assert isinstance(sk, str), "Kyber secret key should be a string"
    assert len(pk) > 0, "Kyber public key string should not be empty"
    assert len(sk) > 0, "Kyber secret key string should not be empty"
    print("SMOKE: Kyber key generation types and non-emptiness OK.")

@requires_dilithium
def test_smoke_dilithium_key_generation_and_types():
    """SMOKE: Dilithium key generation produces non-None string outputs of expected types."""
    print("\nSMOKE: Testing Dilithium key generation...")
    pk, sk = generate_dilithium_keypair()
    assert pk is not None, "Dilithium public key should not be None"
    assert sk is not None, "Dilithium secret key should not be None"
    assert isinstance(pk, str), "Dilithium public key should be a string"
    assert isinstance(sk, str), "Dilithium secret key should be a string"
    assert len(pk) > 0, "Dilithium public key string should not be empty"
    assert len(sk) > 0, "Dilithium secret key string should not be empty"
    print("SMOKE: Dilithium key generation types and non-emptiness OK.")

@requires_kyber
def test_smoke_kem_round_trip(kyber_key_pair_alice, specific_aes_key_32_bytes):
    """SMOKE: KEM wrap and unwrap cycle completes successfully using generated Kyber keys."""
    print("\nSMOKE: Testing KEM round trip...")
    pk_b64 = kyber_key_pair_alice["pk"]
    sk_b64 = kyber_key_pair_alice["sk"]
    
    print(f"SMOKE: Wrapping key (len: {len(specific_aes_key_32_bytes)}) with PK: {pk_b64[:10]}...")
    wrapped_key = kem_wrap_symmetric_key(specific_aes_key_32_bytes, pk_b64)
    assert wrapped_key is not None, "KEM wrapped key should not be None"
    assert isinstance(wrapped_key, str), "KEM wrapped key should be a string"
    print(f"SMOKE: Key wrapped. Wrapped key (start): {wrapped_key[:20]}...")
    
    unwrapped_key = kem_unwrap_symmetric_key(wrapped_key, sk_b64)
    assert unwrapped_key is not None, "KEM unwrapped key should not be None"
    assert unwrapped_key == specific_aes_key_32_bytes, "KEM unwrapped key must match original"
    print("SMOKE: KEM unwrapped key matches original. Round trip OK.")

def test_smoke_aes_round_trip(specific_aes_key_32_bytes, medium_message_bytes):
    """SMOKE: AES encrypt and decrypt cycle completes successfully."""
    print("\nSMOKE: Testing AES round trip...")
    print(f"SMOKE: Encrypting message (len: {len(medium_message_bytes)}) with AES key (len: {len(specific_aes_key_32_bytes)}).")
    encrypted_package = aes_gcm_encrypt(medium_message_bytes, specific_aes_key_32_bytes)
    assert encrypted_package is not None, "AES encrypted package should not be None"
    assert isinstance(encrypted_package, dict), "AES encrypted package should be a dict"
    print(f"SMOKE: Message encrypted. Ciphertext (b64, start): {encrypted_package.get('ciphertext_b64', '')[:20]}...")
    
    decrypted_message = aes_gcm_decrypt(encrypted_package, specific_aes_key_32_bytes)
    assert decrypted_message is not None, "AES decrypted message should not be None"
    assert decrypted_message == medium_message_bytes, "AES decrypted message must match original"
    print("SMOKE: AES decrypted message matches original. Round trip OK.")

@requires_dilithium
def test_smoke_digital_signature_round_trip(dilithium_key_pair_alice, medium_message_bytes):
    """SMOKE: Digital signature sign and verify cycle completes successfully using generated Dilithium keys."""
    print("\nSMOKE: Testing Digital Signature round trip...")
    pk_b64 = dilithium_key_pair_alice["pk"]
    sk_b64 = dilithium_key_pair_alice["sk"]
    
    print(f"SMOKE: Signing message (len: {len(medium_message_bytes)}) with SK: {sk_b64[:10]}...")
    signature = sign_message(medium_message_bytes, sk_b64)
    assert signature is not None, "Digital signature should not be None"
    assert isinstance(signature, str), "Digital signature should be a string"
    print(f"SMOKE: Message signed. Signature (start): {signature[:20]}...")
    
    is_valid = verify_signature(medium_message_bytes, signature, pk_b64)
    assert is_valid is True, "Digital signature verification should return True for valid signature"
    print("SMOKE: Signature verified successfully. Round trip OK.")

def test_smoke_package_api_availability():
    """SMOKE: All functions listed in __all__ are importable and present in the package."""
    print("\nSMOKE: Testing package API availability...")
    import pqc_crypto_package  # Local import to check __all__


    # Ensure __all__ is defined and is a list
    assert hasattr(pqc_crypto_package, "__all__"), "Package is missing __all__ definition."
    assert isinstance(pqc_crypto_package.__all__, list), "__all__ should be a list."
    
    print(f"SMOKE: Checking functions listed in __all__: {pqc_crypto_package.__all__}")
    for func_name in pqc_crypto_package.__all__:
        assert hasattr(pqc_crypto_package, func_name), f"Function '{func_name}' listed in __all__ not found in package."
    print("SMOKE: All package API functions specified in __all__ are available. OK.")


