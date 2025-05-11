# tests/test_pqc_workflow_integration.py
import base64
import json
import os

import pytest

try:
    from Crypto.Random import get_random_bytes  # For DEK generation

    import pqc_crypto_package as pqc
    PQC_PACKAGE_AVAILABLE = True
except ImportError as e:
    PQC_PACKAGE_AVAILABLE = False
    print(f"ImportError in test_pqc_workflow_integration.py: {e}. "
          "Tests will be skipped by markers if pqc_crypto_package or PyCryptodome is not installed.")
    def get_random_bytes(length): # pylint: disable=unused-argument
        return b'\0' * length


# Import markers from conftest
from conftest import requires_dilithium, requires_kyber, requires_pqc_package


@requires_pqc_package
@requires_kyber
@requires_dilithium
def test_full_pqc_encryption_decryption_workflow(
    producer_dilithium_keys,
    consumer_kyber_keys,
    consumer_dilithium_keys,
    kms_kyber_keys,
    original_data_payload_fixture
):
    """
    Tests the end-to-end PQC workflow:
    1. Key Generation for Producer, Consumer, KMS.
    2. Producer encrypts data with a DEK (AES-GCM) and wraps the DEK for KMS (Kyber).
    3. Producer signs a manifest (Dilithium).
    4. Consumer verifies the manifest signature.
    5. Consumer requests the DEK from KMS, signing the request.
    6. KMS verifies the consumer's request signature, performs RLS, unwraps DEK.
    7. KMS re-wraps the DEK for the Consumer.
    8. Consumer unwraps the DEK and decrypts the original data.
    9. Verifies that the decrypted data matches the original data.
    """
    if not PQC_PACKAGE_AVAILABLE: # Should be caught by markers, but as a safeguard
        pytest.skip("pqc_crypto_package not available, skipping workflow test.")

    print("\n--- Running Pytest Integrated PQC Crypto Workflow Test ---")
    print(f"Using KEM: Kyber768 (implicitly by pqc_crypto_package), Signature: Dilithium3 (implicitly)\n")

    # --- Step 1: Key Generation (Provided by fixtures) ---
    print("### Step 1: PQC key pairs for all parties (from fixtures) ###")
    producer_id = producer_dilithium_keys["id"]
    producer_dilithium_pk_b64 = producer_dilithium_keys["pk_b64"]
    producer_dilithium_sk_b64 = producer_dilithium_keys["sk_b64"]
    print(f"[INFO] Producer ({producer_id}) Dilithium PK (b64, first 60): {producer_dilithium_pk_b64[:60]}")

    consumer_id = consumer_kyber_keys["id"] # Assuming Kyber and Dilithium IDs are the same for consumer
    consumer_kyber_pk_b64 = consumer_kyber_keys["pk_b64"]
    consumer_kyber_sk_b64 = consumer_kyber_keys["sk_b64"]
    consumer_dilithium_pk_b64 = consumer_dilithium_keys["pk_b64"]
    consumer_dilithium_sk_b64 = consumer_dilithium_keys["sk_b64"]
    print(f"[INFO] Consumer ({consumer_id}) Kyber PK (b64, first 60): {consumer_kyber_pk_b64[:60]}")
    print(f"[INFO] Consumer ({consumer_id}) Dilithium PK (b64, first 60): {consumer_dilithium_pk_b64[:60]}")

    kms_id = kms_kyber_keys["id"]
    kms_kyber_pk_b64 = kms_kyber_keys["pk_b64"]
    kms_kyber_sk_b64 = kms_kyber_keys["sk_b64"]
    print(f"[INFO] KMS ({kms_id}) Kyber PK (b64, first 60): {kms_kyber_pk_b64[:60]}")

    # --- Step 2: Producer Encrypts and Signs Data ---
    print(f"\n### Step 2: Producer ({producer_id}) encrypts data and signs a manifest ###")
    original_data_payload = original_data_payload_fixture
    original_data_bytes = json.dumps(original_data_payload).encode('utf-8')
    print(f"[INFO] Original data payload defined for task: {original_data_payload['task_id']}")

    dek_bytes = get_random_bytes(32) # AES-256 key
    print(f"[INFO] Generated new Data Encryption Key (DEK) (32 bytes, hex): {dek_bytes.hex()}")

    print("[ACTION] Encrypting data with DEK using AES-GCM...")
    aes_encrypted_data_package = pqc.aes_gcm_encrypt(original_data_bytes, dek_bytes)
    assert aes_encrypted_data_package is not None, "AES-GCM encryption failed"
    assert "ciphertext_b64" in aes_encrypted_data_package
    print(f"[INFO] AES-GCM encrypted data ciphertext (b64, first 60): {aes_encrypted_data_package['ciphertext_b64'][:60]}")

    print(f"[ACTION] Wrapping DEK for KMS ({kms_id}) using KMS Kyber PK...")
    wrapped_dek_for_kms_b64 = pqc.kem_wrap_symmetric_key(dek_bytes, kms_kyber_pk_b64)
    assert wrapped_dek_for_kms_b64 is not None, "KEM wrapping of DEK for KMS failed"
    print(f"[INFO] Wrapped DEK for KMS (b64, first 60): {wrapped_dek_for_kms_b64[:60]}")

    manifest_content = {
        "producer_id": producer_id,
        "task_id": original_data_payload["task_id"],
        "encrypted_data_details": {
            "nonce_b64": aes_encrypted_data_package["nonce_b64"],
            "ciphertext_hash_b64": base64.b64encode(os.urandom(16)).decode('utf-8'), # Placeholder
            "tag_hash_b64": base64.b64encode(os.urandom(16)).decode('utf-8')      # Placeholder
        },
        "wrapped_dek_for_kms_b64": wrapped_dek_for_kms_b64,
        "required_roles_for_dek": ["analyst_role", "supervisor_role"]
    }
    manifest_bytes = json.dumps(manifest_content, sort_keys=True).encode('utf-8')
    print(f"[INFO] Manifest created (length: {len(manifest_bytes)} bytes).")

    print(f"[ACTION] Signing manifest with Producer's ({producer_id}) Dilithium SK...")
    producer_signature_on_manifest_b64 = pqc.sign_message(manifest_bytes, producer_dilithium_sk_b64)
    assert producer_signature_on_manifest_b64 is not None, "Signing of manifest by producer failed"
    print(f"[INFO] Producer's signature on manifest (b64, first 60): {producer_signature_on_manifest_b64[:60]}")

    # --- Step 3: Consumer Verifies Manifest and Requests DEK ---
    print(f"\n### Step 3: Consumer ({consumer_id}) verifies manifest and requests DEK from KMS ({kms_id}) ###")
    print(f"[ACTION] Verifying Producer's ({producer_id}) signature on manifest...")
    is_manifest_signature_valid = pqc.verify_signature(manifest_bytes, producer_signature_on_manifest_b64, producer_dilithium_pk_b64)
    assert is_manifest_signature_valid, "Manifest signature verification failed"
    print("[RESULT] Manifest signature verified successfully.")

    dek_request_to_kms_content = {
        "requesting_node_id": consumer_id,
        "task_id_for_dek": original_data_payload["task_id"],
        "wrapped_dek_reference": wrapped_dek_for_kms_b64
    }
    dek_request_to_kms_bytes = json.dumps(dek_request_to_kms_content, sort_keys=True).encode('utf-8')
    print(f"[INFO] DEK request payload created for KMS (length: {len(dek_request_to_kms_bytes)} bytes).")

    print(f"[ACTION] Signing DEK request with Consumer's ({consumer_id}) Dilithium SK...")
    consumer_signature_on_dek_request_b64 = pqc.sign_message(dek_request_to_kms_bytes, consumer_dilithium_sk_b64)
    assert consumer_signature_on_dek_request_b64 is not None, "Signing of DEK request by consumer failed"
    print(f"[INFO] Consumer's signature on DEK request (b64, first 60): {consumer_signature_on_dek_request_b64[:60]}")

    # --- Step 4: KMS Processes DEK Request ---
    print(f"\n### Step 4: KMS ({kms_id}) processes DEK request from Consumer ({consumer_id}) ###")
    print(f"[ACTION] Verifying Consumer's ({consumer_id}) signature on DEK request...")
    is_consumer_request_signature_valid = pqc.verify_signature(
        dek_request_to_kms_bytes,
        consumer_signature_on_dek_request_b64,
        consumer_dilithium_pk_b64
    )
    assert is_consumer_request_signature_valid, "Consumer's DEK request signature verification failed"
    print("[RESULT] Consumer DEK request signature verified successfully.")

    consumer_roles = ["analyst_role"] # Example roles for the consumer for this test
    print(f"[ACTION] Performing RLS authorization check for Consumer ({consumer_id}) with roles {consumer_roles}...")
    # Robust RLS check by parsing the manifest JSON
    manifest_data_for_rls = json.loads(manifest_bytes.decode('utf-8'))
    required_roles = manifest_data_for_rls.get("required_roles_for_dek", [])
    rls_check_passed = any(role in required_roles for role in consumer_roles)
    assert rls_check_passed, f"Consumer ({consumer_id}) failed RLS authorization check. Required: {required_roles}, Has: {consumer_roles}"
    print("[RESULT] RLS authorization check passed.")

    print(f"[ACTION] KMS unwrapping DEK (originally wrapped by Producer) using KMS's Kyber SK...")
    retrieved_dek_by_kms = pqc.kem_unwrap_symmetric_key(wrapped_dek_for_kms_b64, kms_kyber_sk_b64)
    assert retrieved_dek_by_kms is not None, "KMS failed to unwrap DEK"
    assert retrieved_dek_by_kms == dek_bytes, "DEK unwrapped by KMS does not match original DEK"
    print(f"[INFO] DEK successfully unwrapped by KMS. Retrieved DEK (hex): {retrieved_dek_by_kms.hex()}")

    # --- Step 5: KMS Re-wraps DEK for Consumer ---
    print(f"\n### Step 5: KMS ({kms_id}) re-wraps retrieved DEK for Consumer ({consumer_id}) ###")
    print(f"[ACTION] Re-wrapping DEK for Consumer ({consumer_id}) using Consumer's Kyber PK...")
    wrapped_dek_for_consumer_b64 = pqc.kem_wrap_symmetric_key(retrieved_dek_by_kms, consumer_kyber_pk_b64)
    assert wrapped_dek_for_consumer_b64 is not None, "KMS failed to re-wrap DEK for consumer"
    print(f"[INFO] DEK re-wrapped for Consumer (b64, first 60): {wrapped_dek_for_consumer_b64[:60]}")

    # --- Step 6: Consumer Unwraps DEK and Decrypts Data ---
    print(f"\n### Step 6: Consumer ({consumer_id}) unwraps DEK from KMS and decrypts data ###")
    print(f"[ACTION] Consumer unwrapping DEK (re-wrapped by KMS) using Consumer's Kyber SK...")
    final_dek_by_consumer = pqc.kem_unwrap_symmetric_key(wrapped_dek_for_consumer_b64, consumer_kyber_sk_b64)
    assert final_dek_by_consumer is not None, "Consumer failed to unwrap re-wrapped DEK from KMS"
    print(f"[INFO] Successfully unwrapped final DEK by Consumer. Final DEK (hex): {final_dek_by_consumer.hex()}")

    assert final_dek_by_consumer == dek_bytes, \
        f"Final DEK ({final_dek_by_consumer.hex()}) does NOT match original DEK ({dek_bytes.hex()})!"
    print("[VERIFY] Final DEK obtained by Consumer matches the original DEK generated by Producer.")

    print(f"[ACTION] Decrypting original data payload using final DEK and AES-GCM...")
    decrypted_data_bytes = pqc.aes_gcm_decrypt(aes_encrypted_data_package, final_dek_by_consumer)
    assert decrypted_data_bytes is not None, "AES-GCM decryption of original data failed for Consumer"
    
    decrypted_payload = json.loads(decrypted_data_bytes.decode('utf-8'))
    print(f"[INFO] Data successfully decrypted by Consumer. Decrypted task_id: {decrypted_payload.get('task_id')}")

    # --- Step 7: System Verification ---
    print(f"\n### Step 7: System Verification - Comparing decrypted data with original ###")
    assert decrypted_payload == original_data_payload, \
        "Decrypted data payload DOES NOT MATCH the original data payload."
    print("[SUCCESS] Decrypted data perfectly matches original data payload.")
    print("\n--- Pytest Integrated PQC Crypto Workflow Test PASSED ---")

