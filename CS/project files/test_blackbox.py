
import base64
import binascii  # Correctly import binascii
import json
import os

import pytest

# Import fixtures using relative import from conftest.py in the same 'tests' directory
from conftest import (  # Consolidated imports; non_json_base64_string, # Only import if used; incomplete_kem_package_b64, # Only import if used
    dilithium_key_pair_alice, dilithium_key_pair_bob, empty_message_bytes,
    kyber_key_pair_alice, kyber_key_pair_bob, long_message_bytes,
    malformed_base64_string, medium_message_bytes, requires_dilithium,
    requires_kyber, specific_aes_key_32_bytes)
# Import all public API functions directly from the package
from pqc_crypto_package import (aes_gcm_decrypt, aes_gcm_encrypt,
                                generate_dilithium_keypair,
                                generate_kyber_keypair,
                                kem_unwrap_symmetric_key,
                                kem_wrap_symmetric_key, sign_message,
                                verify_signature)

# Expected raw byte lengths
KYBER768_PK_BYTES = 1184


KYBER768_SK_BYTES = 2400
DILITHIUM3_PK_BYTES = 1952
DILITHIUM3_SK_BYTES = 4000


@pytest.mark.blackbox_package
@requires_kyber
def test_bb_package_kyber_key_generation_validity_and_uniqueness():
    """
    BB Package: Test generate_kyber_keypair() for valid output format, expected raw key lengths,
    and uniqueness across multiple calls.
    """
    print("\nINFO: Testing Kyber key generation validity and uniqueness.")
    pk_b64_1, sk_b64_1 = generate_kyber_keypair()
    print(f"INFO: Generated Kyber pair 1 - PK starts: {pk_b64_1[:10]}..., SK starts: {sk_b64_1[:10]}...")

    assert isinstance(pk_b64_1, str), "Kyber PK 1 should be a string."
    assert len(pk_b64_1) > 0, "Kyber PK 1 string should not be empty."
    assert isinstance(sk_b64_1, str), "Kyber SK 1 should be a string."
    assert len(sk_b64_1) > 0, "Kyber SK 1 string should not be empty."

    try:
        pk_bytes_1 = base64.b64decode(pk_b64_1, validate=True)
        sk_bytes_1 = base64.b64decode(sk_b64_1, validate=True)
    except binascii.Error: # Use the imported name
        pytest.fail("generate_kyber_keypair output (set 1) is not valid Base64.")

    assert len(pk_bytes_1) == KYBER768_PK_BYTES, "Kyber PK 1 raw length unexpected."
    assert len(sk_bytes_1) == KYBER768_SK_BYTES, "Kyber SK 1 raw length unexpected."
    print("INFO: Kyber pair 1 validated (format, length).")

    pk_b64_2, sk_b64_2 = generate_kyber_keypair()
    print(f"INFO: Generated Kyber pair 2 - PK starts: {pk_b64_2[:10]}..., SK starts: {sk_b64_2[:10]}...")
    assert isinstance(pk_b64_2, str) and pk_b64_2 != pk_b64_1, "Second Kyber PK should be different."
    assert isinstance(sk_b64_2, str) and sk_b64_2 != sk_b64_1, "Second Kyber SK should be different."
    print("INFO: Kyber pair 2 validated for uniqueness. Test PASSED.")


@pytest.mark.blackbox_package
@requires_dilithium
def test_bb_package_dilithium_key_generation_validity_and_uniqueness():
    """
    BB Package: Test generate_dilithium_keypair() for valid output format, expected raw key lengths,
    and uniqueness.
    """
    print("\nINFO: Testing Dilithium key generation validity and uniqueness.")
    pk_b64_1, sk_b64_1 = generate_dilithium_keypair()
    print(f"INFO: Generated Dilithium pair 1 - PK starts: {pk_b64_1[:10]}..., SK starts: {sk_b64_1[:10]}...")


    assert isinstance(pk_b64_1, str), "Dilithium PK 1 should be a string."
    assert len(pk_b64_1) > 0, "Dilithium PK 1 string should not be empty."
    assert isinstance(sk_b64_1, str), "Dilithium SK 1 should be a string."
    assert len(sk_b64_1) > 0, "Dilithium SK 1 string should not be empty."
    try:
        pk_bytes_1 = base64.b64decode(pk_b64_1, validate=True)
        sk_bytes_1 = base64.b64decode(sk_b64_1, validate=True)
    except binascii.Error: # Use the imported name
        pytest.fail("generate_dilithium_keypair output (set 1) is not valid Base64.")

    assert len(pk_bytes_1) == DILITHIUM3_PK_BYTES, "Dilithium PK 1 raw length unexpected."
    assert len(sk_bytes_1) == DILITHIUM3_SK_BYTES, "Dilithium SK 1 raw length unexpected."
    print("INFO: Dilithium pair 1 validated (format, length).")

    pk_b64_2, sk_b64_2 = generate_dilithium_keypair()
    print(f"INFO: Generated Dilithium pair 2 - PK starts: {pk_b64_2[:10]}..., SK starts: {sk_b64_2[:10]}...")
    assert isinstance(pk_b64_2, str) and pk_b64_2 != pk_b64_1, "Second Dilithium PK should be different."
    assert isinstance(sk_b64_2, str) and sk_b64_2 != sk_b64_1, "Second Dilithium SK should be different."
    print("INFO: Dilithium pair 2 validated for uniqueness. Test PASSED.")


@pytest.mark.blackbox_package
@requires_kyber
def test_bb_package_kem_workflow_nominal_and_package_structure(kyber_key_pair_alice, specific_aes_key_32_bytes):
    """
    BB Package: Test KEM workflow (wrap then unwrap) with valid inputs.
    Checks: Output types, structural validity of wrapped package (JSON keys, Base64 components),
            successful round trip.
    """
    print("\nINFO: Testing KEM nominal workflow and package structure.")
    recipient_pk_b64 = kyber_key_pair_alice["pk"]
    recipient_sk_b64 = kyber_key_pair_alice["sk"]
    original_key_hex = specific_aes_key_32_bytes.hex()
    print(f"INFO: Original symmetric key to wrap (hex): {original_key_hex}")
    print(f"INFO: Using Kyber PK (Alice) starting: {recipient_pk_b64[:10]}...")

    wrapped_package_b64 = kem_wrap_symmetric_key(specific_aes_key_32_bytes, recipient_pk_b64)
    print(f"INFO: KEM Wrapped package (b64, first 30): {wrapped_package_b64[:30]}...")
    assert isinstance(wrapped_package_b64, str), "kem_wrap_symmetric_key should return a string."
    assert len(wrapped_package_b64) > 50, "Wrapped key package string seems too short."

    try:
        decoded_json_str = base64.b64decode(wrapped_package_b64, validate=True).decode('utf-8')
        pkg_json = json.loads(decoded_json_str)
        expected_keys = ["kem_ct_b64", "aes_nonce_b64", "aes_encrypted_key_b64", "aes_tag_b64"]
        for k in expected_keys:
            assert k in pkg_json, f"Wrapped package JSON missing key: {k}"
            assert isinstance(pkg_json[k], str), f"Value for {k} in wrapped package should be a string."
            base64.b64decode(pkg_json[k], validate=True)
        print("INFO: Wrapped package structure and Base64 components validated.")
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, AssertionError) as e:
        pytest.fail(f"Wrapped key package structure, content, or Base64 encoding is invalid: {e}")

    unwrapped_key_bytes = kem_unwrap_symmetric_key(wrapped_package_b64, recipient_sk_b64)
    print(f"INFO: KEM Unwrapped key (hex): {unwrapped_key_bytes.hex() if unwrapped_key_bytes else 'None'}")
    assert isinstance(unwrapped_key_bytes, bytes), "kem_unwrap_symmetric_key should return bytes."
    assert unwrapped_key_bytes == specific_aes_key_32_bytes, "Unwrapped key must match the original."
    print("INFO: KEM round trip successful. Test PASSED.")


@pytest.mark.blackbox_package
@requires_kyber
def test_bb_package_kem_workflow_unwrap_with_mismatched_sk(kyber_key_pair_alice, kyber_key_pair_bob, specific_aes_key_32_bytes):
    """BB Package: KEM unwrap attempt with a secret key from a different Kyber pair."""
    print("\nINFO: Testing KEM unwrap with mismatched SK.")
    alice_pk_b64 = kyber_key_pair_alice["pk"]
    bob_sk_b64 = kyber_key_pair_bob["sk"] 
    print(f"INFO: Wrapping with Alice's PK ({alice_pk_b64[:10]}...), attempting unwrap with Bob's SK ({bob_sk_b64[:10]}...).")
    assert kyber_key_pair_alice["sk"] != bob_sk_b64, "Test requires distinct secret keys for Alice and Bob."

    wrapped_package_b64 = kem_wrap_symmetric_key(specific_aes_key_32_bytes, alice_pk_b64)
    assert wrapped_package_b64 is not None, "Wrapping for test setup failed."
    print("INFO: Key wrapped successfully with Alice's PK.")

    unwrapped_key_bytes = kem_unwrap_symmetric_key(wrapped_package_b64, bob_sk_b64)
    assert unwrapped_key_bytes is None, "Unwrapping with mismatched SK should fail (return None)."
    print("INFO: Unwrapping with Bob's SK correctly returned None. Test PASSED.")


@pytest.mark.blackbox_package
@requires_kyber
def test_bb_package_kem_wrap_with_malformed_b64_pk_fixture(specific_aes_key_32_bytes, malformed_base64_string):
    """BB Package: Test kem_wrap_symmetric_key with a malformed_base64_string fixture as PK."""
    print("\nINFO: Testing KEM wrap with malformed Base64 PK (fixture).")
    invalid_pk_input = malformed_base64_string
    print(f"INFO: Attempting to wrap with PK: '{invalid_pk_input}'")
    wrapped_package_b64 = kem_wrap_symmetric_key(specific_aes_key_32_bytes, invalid_pk_input)
    assert wrapped_package_b64 is None, "Wrapping with malformed Base64 PK (from fixture) should fail."
    print("INFO: Wrapping correctly returned None for malformed Base64 PK. Test PASSED.")

@pytest.mark.blackbox_package
@requires_kyber
@pytest.mark.parametrize("literal_invalid_pk_input, description", [
    ("not_a_real_key_but_valid_b64=", "Valid Base64, but not a cryptographic key"),
    (12345, "Integer type, not string"),
    (b"bytes_not_str_b64_pk", "Bytes type, when Base64 string is expected by KEM wrap's PK input")
])
def test_bb_package_kem_wrap_with_literal_invalid_pk_types(specific_aes_key_32_bytes, literal_invalid_pk_input, description):
    """BB Package: Test kem_wrap_symmetric_key with various literal invalid public key inputs."""
    print(f"\nINFO: Testing KEM wrap with invalid PK type/content: {description} - Input: '{literal_invalid_pk_input}'")
    wrapped_package_b64 = kem_wrap_symmetric_key(specific_aes_key_32_bytes, literal_invalid_pk_input)
    assert wrapped_package_b64 is None, f"Wrapping with literal invalid PK '{literal_invalid_pk_input}' ({description}) should fail."
    print(f"INFO: Wrapping correctly returned None for invalid PK ({description}). Test PASSED.")


@pytest.mark.blackbox_package
@pytest.mark.parametrize("message_fixture_name", ["short_message_bytes", "medium_message_bytes", "long_message_bytes", "empty_message_bytes"])
def test_bb_package_aes_workflow_nominal_various_messages(specific_aes_key_32_bytes, message_fixture_name, request):
    """
    BB Package: Test AES GCM encrypt/decrypt with various message lengths.
    """
    message_bytes = request.getfixturevalue(message_fixture_name)
    print(f"\nINFO: Testing AES nominal workflow for message type: {message_fixture_name} (length {len(message_bytes)}).")

    encrypted_package = aes_gcm_encrypt(message_bytes, specific_aes_key_32_bytes)
    print(f"INFO: AES Encrypted package (nonce starts): {encrypted_package['nonce_b64'][:10] if encrypted_package else 'None'}...")
    assert isinstance(encrypted_package, dict), "aes_gcm_encrypt should return a dict."
    expected_keys = ["nonce_b64", "ciphertext_b64", "tag_b64"]
    for k in expected_keys:
        assert k in encrypted_package, f"Encrypted AES package missing key: {k}"
        assert isinstance(encrypted_package[k], str), f"Value for {k} in AES package should be a string."
        base64.b64decode(encrypted_package[k], validate=True)
    print("INFO: AES Encrypted package structure and Base64 components validated.")

    decrypted_bytes = aes_gcm_decrypt(encrypted_package, specific_aes_key_32_bytes)
    assert isinstance(decrypted_bytes, bytes), "aes_gcm_decrypt should return bytes."
    assert decrypted_bytes == message_bytes, f"Decrypted AES message must match original for {message_fixture_name}."
    print(f"INFO: AES round trip successful for {message_fixture_name}. Test PASSED.")


@pytest.mark.blackbox_package
def test_bb_package_aes_workflow_decrypt_with_wrong_key(specific_aes_key_32_bytes, medium_message_bytes):
    """BB Package: AES decrypt attempt with an incorrect (but valid length) AES key."""
    print("\nINFO: Testing AES decrypt with wrong key.")
    key_a = specific_aes_key_32_bytes
    key_b = os.urandom(32)
    while key_b == key_a: 
        key_b = os.urandom(32)
    print(f"INFO: Encrypting with key_a (starts {key_a.hex()[:6]}), decrypting with key_b (starts {key_b.hex()[:6]}).")

    encrypted_package = aes_gcm_encrypt(medium_message_bytes, key_a)
    assert encrypted_package is not None, "Encryption for test setup failed."
    print("INFO: Message encrypted successfully with key_a.")

    decrypted_bytes = aes_gcm_decrypt(encrypted_package, key_b)
    assert decrypted_bytes is None, "AES decryption with wrong key should fail (return None)."
    print("INFO: AES decryption with wrong key correctly returned None. Test PASSED.")

@pytest.mark.blackbox_package
@pytest.mark.parametrize("invalid_aes_key, expected_exception_type, error_match_substring", [
    (os.urandom(10), ValueError, "Incorrect AES key length (10 bytes)"),
    ("not_a_bytes_key", ValueError, "Incorrect AES key length (15 bytes)"), # Adjusted based on previous findings
    (b"", ValueError, "Incorrect AES key length (0 bytes)")
])
def test_bb_package_aes_encrypt_with_invalid_key_raises_specific_errors(medium_message_bytes, invalid_aes_key, expected_exception_type, error_match_substring):
    """
    BB Package: Test aes_gcm_encrypt with invalid AES keys, expecting specific exceptions
    and matching a substring of their messages.
    """
    print(f"\nINFO: Testing aes_gcm_encrypt with invalid key: {repr(invalid_aes_key)}, expecting {expected_exception_type.__name__} with message containing '{error_match_substring}'.")
    with pytest.raises(expected_exception_type) as excinfo:
        aes_gcm_encrypt(medium_message_bytes, invalid_aes_key)
    
    assert error_match_substring in str(excinfo.value), \
        f"Expected substring '{error_match_substring}' not found in exception message '{str(excinfo.value)}'"
    print(f"INFO: Correctly raised {expected_exception_type.__name__} with matching message. Test PASSED.")


@pytest.mark.blackbox_package
@requires_dilithium
def test_bb_package_dsa_workflow_nominal_and_signature_format(dilithium_key_pair_alice, medium_message_bytes):
    """
    BB Package: Test DSA sign/verify with valid inputs.
    Checks: Output types, Base64 validity of signature, successful round trip.
    """
    print("\nINFO: Testing DSA nominal workflow and signature format.")
    signer_pk_b64 = dilithium_key_pair_alice["pk"]
    signer_sk_b64 = dilithium_key_pair_alice["sk"]
    print(f"INFO: Using Dilithium SK (Alice) starting: {signer_sk_b64[:10]}...")

    signature_b64 = sign_message(medium_message_bytes, signer_sk_b64)
    print(f"INFO: DSA Signature (b64, first 30): {signature_b64[:30] if signature_b64 else 'None'}...")
    assert isinstance(signature_b64, str), "sign_message should return a string."
    assert len(signature_b64) > 50, "Signature string seems too short."
    try:
        base64.b64decode(signature_b64, validate=True)
        print("INFO: Signature is valid Base64.")
    except binascii.Error: 
        pytest.fail("Signature output from sign_message is not valid Base64.")

    is_valid = verify_signature(medium_message_bytes, signature_b64, signer_pk_b64)
    print(f"INFO: DSA Verification result (correct key): {is_valid}")
    assert is_valid is True, "Verification of a valid signature should return True."
    print("INFO: DSA round trip successful. Test PASSED.")


@pytest.mark.blackbox_package
@requires_dilithium
def test_bb_package_dsa_workflow_verify_with_wrong_pk(dilithium_key_pair_alice, dilithium_key_pair_bob, medium_message_bytes):
    """BB Package: DSA verify attempt with a public key from a different Dilithium pair."""
    print("\nINFO: Testing DSA verify with wrong PK.")
    alice_sk_b64 = dilithium_key_pair_alice["sk"]
    bob_pk_b64 = dilithium_key_pair_bob["pk"] 
    print(f"INFO: Signing with Alice's SK ({alice_sk_b64[:10]}...), attempting verify with Bob's PK ({bob_pk_b64[:10]}...).")
    assert dilithium_key_pair_alice["pk"] != bob_pk_b64, "Test requires distinct public keys for Alice and Bob."

    signature_b64 = sign_message(medium_message_bytes, alice_sk_b64)
    assert signature_b64 is not None, "Signing for test setup failed."
    print("INFO: Message signed successfully with Alice's SK.")

    is_valid = verify_signature(medium_message_bytes, signature_b64, bob_pk_b64)
    assert is_valid is False, "Signature verification with wrong PK should return False."
    print("INFO: DSA verification with wrong PK correctly returned False. Test PASSED.")


@pytest.mark.blackbox_package
@requires_dilithium
def test_bb_package_dsa_workflow_verify_with_altered_message(dilithium_key_pair_alice, medium_message_bytes):
    """BB Package: DSA verify attempt with the original message altered after signing."""
    print("\nINFO: Testing DSA verify with altered message.")
    pk_b64 = dilithium_key_pair_alice["pk"]
    sk_b64 = dilithium_key_pair_alice["sk"]
    original_message = medium_message_bytes
    print(f"INFO: Original message (first 30 bytes): {original_message[:30]}...")

    signature_b64 = sign_message(original_message, sk_b64)
    assert signature_b64 is not None, "Signing for test setup failed."
    print("INFO: Message signed successfully.")

    altered_message = original_message + b" :: data has been altered ::"
    assert original_message != altered_message
    print(f"INFO: Altered message (first 30 bytes): {altered_message[:30]}...")
    is_valid = verify_signature(altered_message, signature_b64, pk_b64)
    assert is_valid is False, "Signature verification with altered message should return False."
    print("INFO: DSA verification with altered message correctly returned False. Test PASSED.")

@pytest.mark.blackbox_package
@requires_dilithium
def test_bb_package_dsa_verify_with_tampered_signature(dilithium_key_pair_alice, medium_message_bytes):
    """BB Package: DSA verify attempt with a signature that has been slightly tampered."""
    print("\nINFO: Testing DSA verify with tampered signature.")
    pk_b64 = dilithium_key_pair_alice["pk"]
    sk_b64 = dilithium_key_pair_alice["sk"]

    signature_b64 = sign_message(medium_message_bytes, sk_b64)
    assert signature_b64 is not None
    print(f"INFO: Original signature (first 30): {signature_b64[:30]}...")

    sig_bytes = base64.b64decode(signature_b64)
    if not sig_bytes: pytest.fail("Signature bytes are empty, cannot tamper.")
    tampered_sig_bytes = sig_bytes[:-1] + bytes([(sig_bytes[-1] ^ 1)]) # Flip one bit
    tampered_signature_b64 = base64.b64encode(tampered_sig_bytes).decode('utf-8')
    assert tampered_signature_b64 != signature_b64
    print(f"INFO: Tampered signature (first 30): {tampered_signature_b64[:30]}...")

    is_valid = verify_signature(medium_message_bytes, tampered_signature_b64, pk_b64)
    assert is_valid is False, "Signature verification with tampered signature should return False."
    print("INFO: DSA verification with tampered signature correctly returned False. Test PASSED.")


@pytest.mark.blackbox_package
@requires_kyber
@requires_dilithium
def test_bb_package_full_scenario_alice_sends_secure_message_to_bob(
    kyber_key_pair_bob, dilithium_key_pair_alice, medium_message_bytes
):
    """
    BB Package: End-to-end scenario: Alice encrypts a message for Bob and signs it. 
                Bob verifies Alice's signature and then decrypts the message.
    """
    print("\nINFO: Starting full end-to-end test: Alice sends secure message to Bob.")
    bob_kem_public_key_b64 = kyber_key_pair_bob["pk"]
    bob_kem_secret_key_b64 = kyber_key_pair_bob["sk"]
    alice_dsa_public_key_b64 = dilithium_key_pair_alice["pk"]
    alice_dsa_secret_key_b64 = dilithium_key_pair_alice["sk"]
    original_message_to_send = medium_message_bytes
    print(f"INFO: Alice's DSA PK (start): {alice_dsa_public_key_b64[:10]}, Bob's KEM PK (start): {bob_kem_public_key_b64[:10]}")

    session_aes_key_bytes = os.urandom(32)
    print(f"INFO: Alice: Generated session AES key (hex, first 6): {session_aes_key_bytes.hex()[:6]}...")

    encrypted_message_package = aes_gcm_encrypt(original_message_to_send, session_aes_key_bytes)
    assert encrypted_message_package is not None, "Alice: AES encryption step failed."
    encrypted_message_package_str = json.dumps(encrypted_message_package, sort_keys=True)
    print(f"INFO: Alice: Message encrypted. Ciphertext (b64, first 10): {encrypted_message_package['ciphertext_b64'][:10]}...")

    wrapped_session_key_b64 = kem_wrap_symmetric_key(session_aes_key_bytes, bob_kem_public_key_b64)
    assert wrapped_session_key_b64 is not None, "Alice: KEM wrapping of session key failed."
    print(f"INFO: Alice: Session key KEM-wrapped for Bob (b64, first 10): {wrapped_session_key_b64[:10]}...")

    data_bundle_to_sign_dict = {
        "encrypted_content": encrypted_message_package_str,
        "wrapped_ephemeral_key": wrapped_session_key_b64
    }
    data_bundle_to_sign_bytes = json.dumps(data_bundle_to_sign_dict, sort_keys=True).encode('utf-8')

    alice_signature_b64 = sign_message(data_bundle_to_sign_bytes, alice_dsa_secret_key_b64)
    assert alice_signature_b64 is not None, "Alice: Signing the data bundle failed."
    print(f"INFO: Alice: Data bundle signed (signature b64, first 10): {alice_signature_b64[:10]}...")

    reconstructed_data_bundle_to_verify_dict = {
        "encrypted_content": encrypted_message_package_str,
        "wrapped_ephemeral_key": wrapped_session_key_b64
    }
    reconstructed_data_bundle_to_verify_bytes = json.dumps(reconstructed_data_bundle_to_verify_dict, sort_keys=True).encode('utf-8')
    assert reconstructed_data_bundle_to_verify_bytes == data_bundle_to_sign_bytes, \
        "Bob: Mismatch in reconstructing the data bundle for signature verification."

    is_signature_authentic = verify_signature(
        reconstructed_data_bundle_to_verify_bytes,
        alice_signature_b64,
        alice_dsa_public_key_b64
    )
    assert is_signature_authentic is True, "Bob: Signature verification failed. Message authenticity or integrity compromised."
    print("INFO: Bob: Alice's signature verified successfully.")

    bob_unwrapped_session_key_bytes = kem_unwrap_symmetric_key(wrapped_session_key_b64, bob_kem_secret_key_b64)
    assert bob_unwrapped_session_key_bytes is not None, "Bob: KEM unwrapping of session key failed."
    assert bob_unwrapped_session_key_bytes == session_aes_key_bytes, \
        "Bob: Unwrapped session key does not match Alice's original session key."
    print(f"INFO: Bob: Session key KEM-unwrapped successfully (hex, first 6): {bob_unwrapped_session_key_bytes.hex()[:6]}...")

    decrypted_message_by_bob_bytes = aes_gcm_decrypt(encrypted_message_package, bob_unwrapped_session_key_bytes)
    assert decrypted_message_by_bob_bytes is not None, "Bob: AES decryption of the message data failed."
    print("INFO: Bob: Message decrypted successfully.")
    
    assert decrypted_message_by_bob_bytes == original_message_to_send, \
        "Bob: Final decrypted message does not match Alice's original sent message."
    print("INFO: Bob: Decrypted message matches original. Full scenario PASSED.")


